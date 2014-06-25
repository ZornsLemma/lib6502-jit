/* Copyright (c) 2014 Steven Flintham
 * 
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the 'Software'),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, provided that the above copyright notice(s) and this
 * permission notice appear in all copies of the Software and that both the
 * above copyright notice(s) and this permission notice appear in supporting
 * documentation.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS'.  USE ENTIRELY AT YOUR OWN RISK.
 */

#include "FunctionBuilder.h"

// Throughout this file we must be careful to avoid incorrect wrap-around
// handling; for example, it's wrong to do memory[pc + 2] because if pc is
// 0xffff this will access off the end of memory. We must always use uint16_t
// intermediate values to get the right wrapping behaviour. Similar
// considerations apply when using zero-page addressing; we must ensure we wrap
// around at 0xff.

#include "config.h"

#include <algorithm>
#include <assert.h>
#include <iomanip>
#include "llvm/Analysis/Passes.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/TypeBuilder.h"

#if defined HAVE_LLVM_ANALYSIS_VERIFIER_H
    #include "llvm/Analysis/Verifier.h"
#elif defined HAVE_LLVM_IR_VERIFIER_H
    #include "llvm/IR/Verifier.h"
#else
    #error Need LLVM Verifier.h
#endif

#include "llvm/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
#include <sstream>

#include "AddressRange.h"
#include "const.h"
#include "Function.h"
#include "LLVMStuff.h"
#include "M6502Internal.h"
#include "Registers.h"
#include "util.h"



namespace llvm
{
    template<bool xcompile> 
    class TypeBuilder<M6502, xcompile>
    {
    public:
        static StructType *get(LLVMContext &context)
        {
            static StructType *t = StructType::create(context, "M6502");
            return t;
        }
    };

    template<bool xcompile> 
    class TypeBuilder<Registers, xcompile>
    {
    public:
        static StructType *get(LLVMContext &context)
        {
            static StructType *t = StructType::create("Registers",
                TypeBuilder<types::i<8>, xcompile>::get(context), // a
                TypeBuilder<types::i<8>, xcompile>::get(context), // x
                TypeBuilder<types::i<8>, xcompile>::get(context), // y
                TypeBuilder<types::i<8>, xcompile>::get(context), // s
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_n
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_v
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_d
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_i
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_z
                TypeBuilder<JitBool    , xcompile>::get(context), // flag_c
                TypeBuilder<types::i<16>, xcompile>::get(context), // pc
                TypeBuilder<types::i<16>, xcompile>::get(context), // addr
                TypeBuilder<types::i<8>, xcompile>::get(context), // data
                NULL);
            return t;
        }
    };
}

namespace
{
    const std::string hex_prefix = "&";

    bool callback_in_bounds(const M6502_Callback *callbacks, 
                            const AddressRange &bounds)
    {
        for (AddressRange::const_iterator it = bounds.begin(); 
             it != bounds.end(); ++it)
        {
            if (callbacks[*it] != 0)
            {
                return true;
            }
        }
        return false;
    }
}



// BoundedAddress contains an llvm::Value of type i16 which refers to
// an address in the emulated memory. It additionally contains a range of
// possible addresses which the llvm::Value can evaluate to (derived from the
// addressing mode which created it). This is used to optimise the generated
// code.

class FunctionBuilder::BoundedAddress
{
public:
    // Construct a BoundedAddress with the widest possible bounds; this
    // is always safe, but if possible should be avoided as it reduces
    // optimisation potential.
    BoundedAddress(FunctionBuilder &fb, llvm::Value *addr);

    // Construct a BoundedAddress with the given bounds.
    BoundedAddress(FunctionBuilder &fb, llvm::Value *addr, 
                   const AddressRange &bounds);

    llvm::Value *addr() const
    {
        return addr_;
    }

    const AddressRange &bounds() const
    {
        return bounds_;
    }

    friend
    std::ostream &operator<<(std::ostream &s, const BoundedAddress &ba)
    {
        std::stringstream t;
        t << "[0x" << std::hex << std::setfill('0') << std::setw(4) << 
             ba.bounds().range_begin() << ", 0x" << std::setw(4) << 
             ba.bounds().range_end() << ")";
        s << t.str();
        return s;
    }

private:
    llvm::Value *addr_;
    AddressRange bounds_;
};

FunctionBuilder::BoundedAddress::BoundedAddress(
  FunctionBuilder &fb, llvm::Value *addr)
: addr_(addr), bounds_(0, memory_size)
{
    assert(addr->getType() == fb.i16_type_);
}

FunctionBuilder::BoundedAddress::BoundedAddress(
    FunctionBuilder &fb, llvm::Value *addr, const AddressRange &bounds)
: addr_(addr), bounds_(bounds)
{
    assert(addr->getType() == fb.i16_type_);

#ifndef NDEBUG
    llvm::ConstantInt *addr_ci = llvm::dyn_cast<llvm::ConstantInt>(addr);
    if (addr_ci != 0)
    {
        // We can verify the claimed bounds at compile time.
        uint16_t addr16 = addr_ci->getLimitedValue();
        assert(addr16 == bounds.range_begin());
        assert(addr16 == (bounds.range_end() - 1));
    }
    else
    {
        // We can't verify the claimed bounds at compile time, so generate code 
        // to check at runtime.

        llvm::BasicBlock *bounds_maybe_ok_block = 
            llvm::BasicBlock::Create(fb.context_, "bounds_maybe_ok_block", 
                                     fb.llvm_function_);
        llvm::BasicBlock *bounds_not_ok_block = 
            llvm::BasicBlock::Create(fb.context_, "bounds_not_ok");
        llvm::BasicBlock *bounds_ok_block = 
            llvm::BasicBlock::Create(fb.context_, "bounds_ok");

        if (bounds.range_end() <= memory_size)
        {
            TRACE("Generating bounds check code for non-wrapped case");
            llvm::Value *lower_bound_ok = 
                fb.builder_.CreateICmpUGE(
                    addr, fb.constant_u16(bounds.range_begin()));
            fb.builder_.CreateCondBr(lower_bound_ok, bounds_maybe_ok_block, 
                                     bounds_not_ok_block);
            fb.builder_.SetInsertPoint(bounds_maybe_ok_block);
            llvm::Value *upper_bound_ok = 
                fb.builder_.CreateICmpULE(
                    addr, fb.constant_u16(bounds.range_end() - 1));
            fb.builder_.CreateCondBr(upper_bound_ok, bounds_ok_block, 
                                     bounds_not_ok_block);
        }
        else
        {
            TRACE("Generating bounds check code for wrapped case");
            llvm::Value *in_upper_range = 
                fb.builder_.CreateICmpUGE(
                    addr, fb.constant_u16(bounds.range_begin()));
            fb.builder_.CreateCondBr(in_upper_range, bounds_ok_block, 
                                     bounds_maybe_ok_block);
            fb.builder_.SetInsertPoint(bounds_maybe_ok_block);
            // We want to truncate bounds.range_end() - 1 to 16 bits here.
            llvm::Value *in_lower_range = 
                fb.builder_.CreateICmpULE(
                    addr, fb.constant_u16(bounds.range_end() - 1));
            fb.builder_.CreateCondBr(in_lower_range, bounds_ok_block, 
                                     bounds_not_ok_block);
        }

        fb.llvm_function_->getBasicBlockList().push_back(bounds_not_ok_block);
        fb.builder_.SetInsertPoint(bounds_not_ok_block);
        fb.return_invalid_bounds();

        fb.llvm_function_->getBasicBlockList().push_back(bounds_ok_block);
        fb.builder_.SetInsertPoint(bounds_ok_block);
    }
#endif
}



FunctionBuilder::FunctionBuilder(
    M6502 *mpu, const uint8_t *ct_memory, JitBool *code_at_address, 
    uint16_t address)
: built_(false),
  mpu_(mpu),
  code_at_address_(code_at_address),
  address_(address),
  ct_memory_(ct_memory),
  callbacks_(*(mpu->callbacks)),
  instructions_(0),
  max_instructions_(std::max(1, mpu->internal->max_instructions_)),
  context_(llvm::getGlobalContext()),
  native_int_type_(llvm::TypeBuilder<int, false>::get(context_)),
  callback_type_(llvm::TypeBuilder<M6502_Callback, false>::get(context_)),
  i1_type_(llvm::TypeBuilder<llvm::types::i<1>, false>::get(context_)),
  i8_type_(llvm::TypeBuilder<llvm::types::i<8>, false>::get(context_)),
  i16_type_(llvm::TypeBuilder<llvm::types::i<16>, false>::get(context_)),
  i32_type_(llvm::TypeBuilder<llvm::types::i<32>, false>::get(context_)),
  i64_type_(llvm::TypeBuilder<llvm::types::i<64>, false>::get(context_)),
  jit_bool_type_(llvm::TypeBuilder<JitBool, false>::get(context_)),
  builder_(mpu_->internal->llvm_stuff_.builder_),
  address_block_(),
  code_generated_for_address_()
{
    llvm::FunctionType *ft = llvm::TypeBuilder<int(), false>::get(context_);
    std::stringstream name;
    name << "x" << std::hex << std::setw(4) << std::setfill('0') << address_;
    llvm_function_ = llvm::Function::Create(
        ft, llvm::Function::PrivateLinkage, name.str(), 
        mpu_->internal->llvm_stuff_.module_.get());

    llvm::BasicBlock *BB = 
        llvm::BasicBlock::Create(context_, "prologue", llvm_function_);
    builder_.SetInsertPoint(BB);

    mpu_llvm_ = constant_ptr(mpu, "mpu");
    code_at_address_llvm_ = constant_ptr(code_at_address, "code_at_address");
    registers_ = constant_ptr(&(mpu->internal->registers_), "registers");
    read_callbacks_ = constant_ptr(callbacks_.read, "read_callbacks");
    write_callbacks_ = constant_ptr(callbacks_.write, "write_callbacks");
    call_callbacks_ = constant_ptr(callbacks_.call, "call_callbacks");
    memory_base_ = constant_ptr(mpu->memory, "memory");

    function_result_ = 
        builder_.CreateAlloca(native_int_type_, 0, "function_result");

    // Function prologue: Copy the registers from Registers into local
    // variables for use. The epilogue will reverse this process before the
    // function returns for registers which actually get modified. (The
    // LLVM optimiser is then able to remove loads which would just load
    // unused values.)
    initialise_i8_reg(a_     , 0, "a");
    initialise_i8_reg(x_     , 1, "x");
    initialise_i8_reg(y_     , 2, "y");
    initialise_i8_reg(s_     , 3, "s");
    initialise_jb_reg(flag_n_, 4, "flag_n");
    initialise_jb_reg(flag_v_, 5, "flag_v");
    initialise_jb_reg(flag_d_, 6, "flag_d");
    initialise_jb_reg(flag_i_, 7, "flag_i");
    initialise_jb_reg(flag_z_, 8, "flag_z");
    initialise_jb_reg(flag_c_, 9, "flag_c");

    pc_     = builder_.CreateAlloca(i16_type_, 0, "pc");
    builder_.CreateStore(
        builder_.CreateLoad(
            builder_.CreateStructGEP(registers_, 10), false, "pc"), 
        pc_);

    // Temporary variable used when invoking read callbacks; no need to
    // initialise.
    read_callback_result_ = 
        builder_.CreateAlloca(i8_type_, 0, "read_callback_result");

    // Temporary variables for ADC/SBC implementation; no need to initialise.
    p_tmp_ = builder_.CreateAlloca(i8_type_, 0, "p_tmp");
    l_tmp_ = builder_.CreateAlloca(i8_type_, 0, "l_tmp");
    s_tmp_ = builder_.CreateAlloca(i16_type_, 0, "s_tmp");
    t_tmp_ = builder_.CreateAlloca(i16_type_, 0, "t_tmp");

    epilogue_ = llvm::BasicBlock::Create(context_, "epilogue");
}

// The Register objects are initialised using these functions instead of
// constructors mainly because we need a builder_ with an associated BasicBlock
// to initialise a Register, and we don't have that when the FunctionBuilder
// object is first constructed.

void FunctionBuilder::initialise_i8_reg(
    Register &r, int structure_index, const std::string &name)
{
    llvm::Value *v = builder_.CreateAlloca(i8_type_, 0, name);
    builder_.CreateStore(
        builder_.CreateLoad(
            builder_.CreateStructGEP(registers_, structure_index), false, name), 
        v);
    r.v_ = v;
    r.modified_ = false;
}

void FunctionBuilder::initialise_jb_reg(
    Register &r, int structure_index, const std::string &name)
{
    llvm::Value *v = builder_.CreateAlloca(jit_bool_type_, 0, name);
    builder_.CreateStore(
        builder_.CreateLoad(
            builder_.CreateStructGEP(registers_, structure_index), false, name), 
        v);
    r.v_ = v;
    r.modified_ = false;
}

void FunctionBuilder::ensure_address_block_created(uint16_t addr)
{
    if (address_block_[addr] == 0)
    {
        std::stringstream s;
        s << "l" << std::hex << std::setw(4) << std::setfill('0') << addr;
        address_block_[addr] = 
            llvm::BasicBlock::Create(context_, s.str(), llvm_function_);
    }
}

boost::shared_ptr<Function> FunctionBuilder::build()
{
    // This can't be invoked twice on the same FunctionBuilder object;
    // at present, for example, attempts to insert into 'epilogue_' crash
    // (presumably because it's been used to generate code already). There
    // is no reason to do this and I'm not going to convolute things to make
    // this pointless case work. Even asserting that this doesn't happen
    // seems like overkill, but let's do it anyway.
    assert(!built_);

    // While it doesn't strictly matter, the fact that pending_ is a std::set
    // means it will internally sort the addresses. This makes it more likely
    // that multiple backward jumps will only result in one stretch of code
    // being produced, since the furthest jump backwards will be JITted first.
    pending_.insert(address_);
    while (!pending_.empty())
    {
        // We take addresses to JIT at from pending_ to start with, and when
        // there's no "better" address...
        uint16_t ct_pc = *(pending_.begin());

        // ... but if we can continue JITting where we left off, we prefer
        // to do that. Since each block of code emitted by build_at() is
        // independent, this doesn't alter the behaviour of the generated
        // code, but it avoids gratuitous discontinuities in the generated
        // code compared with the source machine code.
        do
        {
            pending_.erase(ct_pc);
            uint16_t new_ct_pc = build_at(ct_pc);
            if (new_ct_pc == ct_pc)
            {
                // build_at() did no work.
            }
            else if (new_ct_pc > ct_pc)
            {
                code_range_.insert(AddressRange(ct_pc, new_ct_pc));
            }
            else
            {
                // PC wrapped around during the translation.
                uint32_t range_end = new_ct_pc;
                range_end += memory_size;
                code_range_.insert(AddressRange(ct_pc, range_end));
            }
            ct_pc = new_ct_pc;
        }
        while (pending_.find(ct_pc) != pending_.end());
    }

    LLVMStuff &llvm_stuff = mpu_->internal->llvm_stuff_;
    llvm::FunctionPassManager fpm(llvm_stuff.module_.get());

#ifdef HAVE_LLVM_DATA_LAYOUT_PASS
    fpm.add(new llvm::DataLayoutPass(llvm_stuff.module_.get()));
#else
    fpm.add(
        new llvm::DataLayout(*llvm_stuff.execution_engine_->getDataLayout()));
#endif
    fpm.add(llvm::createBasicAliasAnalysisPass());
    fpm.add(llvm::createPromoteMemoryToRegisterPass());
    fpm.add(llvm::createInstructionCombiningPass());
    fpm.add(llvm::createReassociatePass());
    fpm.add(llvm::createGVNPass());
    fpm.add(llvm::createCFGSimplificationPass());
    fpm.doInitialization();

    // We could have passed llvm_function_ to BasicBlock::Create() earlier
    // and then we wouldn't need to do this push_back() here, but doing
    // this means the epilogue appears at the end of the IR. It makes no
    // functional difference but it seems slightly more logical to read.
    llvm_function_->getBasicBlockList().push_back(epilogue_);

    builder_.SetInsertPoint(epilogue_);
    if (a_.modified_)
    {
        builder_.CreateStore(
            builder_.CreateLoad(a_.v_), 
            builder_.CreateStructGEP(registers_, 0));
    }
    if (x_.modified_)
    {
        builder_.CreateStore(
            builder_.CreateLoad(x_.v_), 
            builder_.CreateStructGEP(registers_, 1));
    }
    if (y_.modified_)
    {
        builder_.CreateStore(
            builder_.CreateLoad(y_.v_), 
            builder_.CreateStructGEP(registers_, 2));
    }
    if (s_.modified_)
    {
        builder_.CreateStore(
            builder_.CreateLoad(s_.v_), 
            builder_.CreateStructGEP(registers_, 3));
    }
    if (flag_n_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_n_), 
            builder_.CreateStructGEP(registers_, 4));
    }
    if (flag_v_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_v_), 
            builder_.CreateStructGEP(registers_, 5));
    }
    if (flag_d_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_d_), 
            builder_.CreateStructGEP(registers_, 6));
    }
    if (flag_i_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_i_), 
            builder_.CreateStructGEP(registers_, 7));
    }
    if (flag_z_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_z_), 
            builder_.CreateStructGEP(registers_, 8));
    }
    if (flag_c_.modified_)
    {
        builder_.CreateStore(
            register_load(flag_c_), 
            builder_.CreateStructGEP(registers_, 9));
    }
    builder_.CreateStore(
        builder_.CreateLoad(pc_), 
        builder_.CreateStructGEP(registers_, 10));

    builder_.CreateRet(builder_.CreateLoad(function_result_));

    #ifdef LOG
        std::string unoptimised_ir;
        {
            llvm::raw_string_ostream s(unoptimised_ir);
            llvm_function_->print(s);
            s.str();
        }
    #endif
    llvm::verifyFunction(*llvm_function_);

    fpm.run(*llvm_function_);
    #ifdef LOG
        std::string optimised_ir;
        {
            llvm::raw_string_ostream s(optimised_ir);
            llvm_function_->print(s);
            s.str();
        }
    #endif

    boost::shared_ptr<Function> f(
        new Function(mpu_, address_, code_range_, optimistic_writes_, 
                     llvm_function_));
    #ifdef LOG
        f->set_disassembly(disassembly_.str());
        f->set_unoptimised_ir(unoptimised_ir);
        f->set_optimised_ir(optimised_ir);
    #endif

    built_ = true;
    return f;
}

// This translates a linear stream of 6502 instructions into LLVM IR. The
// generation stops either when we've translated enough 6502 instructions
// or when we hit an instruction which unconditionally transfers control
// elsewhere. Branch targets found during the translation are added to pending_
// for further consideration; at a minimum, address_block[] entries with
// associated code to transfer control to those addresses must be generated
// for each of these before terminating the build process for the function.
//
// The address of the first byte not translated is returned.
uint16_t FunctionBuilder::build_at(uint16_t ct_pc)
{
    TRACE("Translating linear stream of instructions at 0x" << std::hex <<
          std::setfill('0') << std::setw(4) << ct_pc);

    const uint16_t original_ct_pc = ct_pc;
    // If we already translated this stretch of code, we don't need to do
    // anything at all.
    if (code_generated_for_address_[ct_pc])
    {
        TRACE("Already translated this linear stream");
        return ct_pc;
    }

    while (true)
    {
        TRACE("Translating at 0x" << std::hex << std::setfill('0') << 
              std::setw(4) << ct_pc << ", opcode 0x" << std::setw(2) <<
              static_cast<int>(ct_memory_[ct_pc]));

        const uint16_t this_opcode_at = ct_pc;

        if (code_generated_for_address_[ct_pc])
        {
            // We already translated this instruction, so we can stop
            // translating and just jump there. Since this is just linear
            // flow of control from the perspective of the 6502 code, this
            // cannot trigger a call callback.
            TRACE("Already translated this instruction");
            if (builder_.GetInsertBlock()->getTerminator() == 0)
            {
                control_transfer_to(constant_u16(ct_pc), opcode_implicit);
            }
            break;
        }

        // Each instruction forms its own basic block (since we build up the
        // IR as we go, we can't know where we might want to branch into,
        // so we cannot merge multiple instructions into a single basic
        // block). Basic blocks must end with a terminator, so if there isn't
        // already a terminator at the end of the previous instruction's basic
        // block, we insert an unconditional branch to this instruction's
        // basic block. If there is already a terminator, we stop translating
        // this stream of instructions unless this is the first instruction
        // in this linear sequence; this way we avoid generating unreachable
        // code if the previous instruction (for example) returned some kind
        // of status code to our caller. (If the following instruction is
        // reachable in some other way, it will be translated separately -
        // as the first instruction in a linear sequence - because it will
        // be present in pending.)
        bool insert_block_has_terminator = 
            (builder_.GetInsertBlock()->getTerminator() != 0);
        if (insert_block_has_terminator && (ct_pc != original_ct_pc))
        {
            TRACE("Not translating as not first instruction in linear stream "
                  "and previous instruction's basic block has a terminator");
            break;
        }
        ensure_address_block_created(ct_pc);
        if (!insert_block_has_terminator)
        {
            builder_.CreateBr(address_block_[ct_pc]);
        }
        builder_.SetInsertPoint(address_block_[ct_pc]);

        // Note that we only set this flag for the opcode byte, not the
        // whole length of the instruction. Apart from being easiest,
        // this is actually correct. Someone might do LDA #<opcode for
        // LDA #>:STA <opcode for RTS> or something weird like that and
        // interleave instructions.
        code_generated_for_address_[ct_pc] = true;

        if (instructions_ >= max_instructions_)
        {
            TRACE("Translated maximum number of instructions");
            // We must *not* use control_transfer_to() here; it would see
            // that we have set code_generated_for_address_ and generate a
            // branch to here, i.e. an infinite loop. It is correct that we
            // have set code_generated_for_address_ since we must set that
            // if we generate a corresponding address_block entry and we must
            // do that so that any branches to this address can be resolved.
            return_control_transfer_direct(constant_u16(ct_pc));
            break;
        }
        ++instructions_;

        uint8_t opcode = ct_memory_[ct_pc];
        if (opcode == opcode_brk)
        {
            disassemble1(ct_pc, "BRK");

            llvm::Value *new_pc_low = memory_read(abs(0xfffe));
            llvm::Value *new_pc_high = memory_read(abs(0xffff));
            llvm::Value *new_pc = create_u16(new_pc_low, new_pc_high);

            // Because BRK pushes three bytes onto the stack, we devolve
            // responsibility for checking for code living on the stack
            // being modified to our caller (by returning result_brk), so
            // we use push*raw() here. (We don't support optimistic writes;
            // BRK isn't performance critical so there's no payoff for the
            // extra complexity.)
 
            uint16_t pc_to_stack = this_opcode_at + 2;
            push_u16_raw(pc_to_stack);

            llvm::Value *p = flag_byte();
            p = builder_.CreateOr(p, constant_u8(flagB | flagX));
            push_u8_raw(p);

            register_store(constant_jb(jit_bool_true), flag_i_);
            register_store(constant_jb(jit_bool_false), flag_d_);

            return_brk(new_pc);
        }
        else if (opcode == 0x01)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA (", operand, ",X)");
            ora(memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x02)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x03)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x04)
        {
            uint8_t operand;
            disassemble2(ct_pc, "TSB ", operand);
            memory_op(&FunctionBuilder::tsb, zp(operand), ct_pc);
        }
        else if (opcode == 0x05)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA ", operand);
            ora(memory_read(zp(operand)));
        }
        else if (opcode == 0x06)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ASL ", operand);
            memory_op(&FunctionBuilder::asl, zp(operand), ct_pc);
        }
        else if (opcode == 0x07)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x08)
        {
            disassemble1(ct_pc, "PHP");

            llvm::Value *p = flag_byte();
            p = builder_.CreateOr(p, constant_u8(flagB | flagX));
            push_u8(p, ct_pc);
        }
        else if (opcode == 0x09)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA #", operand);
            ora(constant_u8(operand));
        }
        else if (opcode == 0x0a)
        {
            disassemble1(ct_pc, "ASL A");
            register_op(&FunctionBuilder::asl, a_);
        }
        else if (opcode == 0x0b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x0c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "TSB ", operand);
            memory_op(&FunctionBuilder::tsb, abs(operand), ct_pc);
        }
        else if (opcode == 0x0d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ORA ", operand);
            ora(memory_read(abs(operand)));
        }
        else if (opcode == 0x0e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ASL ", operand);
            memory_op(&FunctionBuilder::asl, abs(operand), ct_pc);
        }
        else if (opcode == 0x0f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bpl)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BPL ", target);
            pending_.insert(target);
            branch(flag_n_, false, target);
        }
        else if (opcode == 0x11)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA (", operand, "),Y");
            ora(memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0x12)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA (", operand, ")");
            ora(memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0x13)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x14)
        {
            uint8_t operand;
            disassemble2(ct_pc, "TRB ", operand);
            memory_op(&FunctionBuilder::trb, zp(operand), ct_pc);
        }
        else if (opcode == 0x15)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ORA ", operand, ",X");
            ora(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x16)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ASL ", operand, ",X");
            memory_op(&FunctionBuilder::asl, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0x17)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x18)
        {
            disassemble1(ct_pc, "CLC");
            register_store(constant_jb(jit_bool_false), flag_c_);
        }
        else if (opcode == 0x19)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ORA ", operand, ",Y");
            ora(memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0x1a)
        {
            disassemble1(ct_pc, "INC A");
            register_op(&FunctionBuilder::inc, a_);
        }
        else if (opcode == 0x1b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x1c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "TRB ", operand);
            memory_op(&FunctionBuilder::trb, abs(operand), ct_pc);
        }
        else if (opcode == 0x1d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ORA ", operand, ",X");
            ora(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0x1e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ASL ", operand, ",X");
            memory_op(
                &FunctionBuilder::asl, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0x1f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_jsr)
        {
            uint16_t operand;
            disassemble3(ct_pc, "JSR ", operand);
            uint16_t mangled_return_addr = ct_pc - 1;

            // We are pushing two bytes onto the stack here and possibly
            // requiring our caller to handle the control transfer, so the
            // standard mechanisms for handling writes to code and control
            // transfer aren't enough. control_transfer_to() contains special
            // logic for JSR and we just use push_u16_raw() here.
            push_u16_raw(mangled_return_addr);

            // We generally want to translate the subroutine code into
            // this function, so control_transfer_to() can perform the
            // control transfer with a simple branch. However, if there is
            // a call callback, control_transfer_to() will have to arrange
            // a control transfer via the generated function's caller. It
            // would be strictly harmless for us to translate the subroutine
            // code anyway, as it will just never be executed, but it is
            // both pointless and makes the generated IR less readable (it
            // has a superficially buggy appearance, since it will show a
            // translation of possibly junk code at the callback address
            // which may never actually execute).
            bool is_call_callback = (callbacks_.call[operand] != 0);
            if (!is_call_callback)
            {
                pending_.insert(operand);

                // We can predict that the RTS in the subroutine we are
                // about to call will return to the immediately following
                // instruction.  (This is not guaranteed; the subroutine
                // might fiddle with the stack. If that happens the "code"
                // at ct_pc might be junk, but that's an acceptable risk;
                // we will translate it but it will never be executed, and
                // any stream of bytes can be translated even if the code
                // is nonsense.)
                pending_.insert(ct_pc);
                predicted_rts_targets_[operand].insert(ct_pc);
            }

            control_transfer_to(constant_u16(operand), opcode);
        }
        else if (opcode == 0x21)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND (", operand, ",X)");
            And(memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x22)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x23)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x24)
        {
            uint8_t operand;
            disassemble2(ct_pc, "BIT ", operand);
            bit(memory_read(zp(operand)));
        }
        else if (opcode == 0x25)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND ", operand);
            And(memory_read(zp(operand)));
        }
        else if (opcode == 0x26)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ROL ", operand);
            memory_op(&FunctionBuilder::rol, zp(operand), ct_pc);
        }
        else if (opcode == 0x27)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x28)
        {
            disassemble1(ct_pc, "PLP");
            pop_flags();
        }
        else if (opcode == 0x29)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND #", operand);
            And(constant_u8(operand));
        }
        else if (opcode == 0x2a)
        {
            disassemble1(ct_pc, "ROL A");
            register_op(&FunctionBuilder::rol, a_);
        }
        else if (opcode == 0x2b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x2c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "BIT ", operand);
            bit(memory_read(abs(operand)));
        }
        else if (opcode == 0x2d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "AND ", operand);
            And(memory_read(abs(operand)));
        }
        else if (opcode == 0x2e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ROL ", operand);
            memory_op(&FunctionBuilder::rol, abs(operand), ct_pc);
        }
        else if (opcode == 0x2f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bmi)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BMI ", target);
            pending_.insert(target);
            branch(flag_n_, true, target);
        }
        else if (opcode == 0x31)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND (", operand, "),Y");
            And(memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0x32)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND (", operand, ")");
            And(memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0x33)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x34)
        {
            uint8_t operand;
            disassemble2(ct_pc, "BIT ", operand, ",X");
            bit(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x35)
        {
            uint8_t operand;
            disassemble2(ct_pc, "AND ", operand, ",X");
            And(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x36)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ROL ", operand, ",X");
            memory_op(&FunctionBuilder::rol, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0x37)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x38)
        {
            disassemble1(ct_pc, "SEC");
            register_store(constant_jb(jit_bool_true), flag_c_);
        }
        else if (opcode == 0x39)
        {
            uint16_t operand;
            disassemble3(ct_pc, "AND ", operand, ",Y");
            And(memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0x3a)
        {
            disassemble1(ct_pc, "DEC A");
            register_op(&FunctionBuilder::dec, a_);
        }
        else if (opcode == 0x3b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x3c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "BIT ", operand, ",X");
            bit(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0x3d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "AND ", operand, ",X");
            And(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0x3e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ROL ", operand, ",X");
            memory_op(
                &FunctionBuilder::rol, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0x3f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_rti)
        {
            disassemble1(ct_pc, "RTI");
            pop_flags();
            llvm::Value *new_pc = pop_u16();
            control_transfer_to(new_pc, opcode);
        }
        else if (opcode == 0x41)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR (", operand, ",X)");
            eor(memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x42)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x43)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x44)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x45)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR ", operand);
            eor(memory_read(zp(operand)));
        }
        else if (opcode == 0x46)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LSR ", operand);
            memory_op(&FunctionBuilder::lsr, zp(operand), ct_pc);
        }
        else if (opcode == 0x47)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x48)
        {
            disassemble1(ct_pc, "PHA");
            push_u8(register_load(a_), ct_pc);
        }
        else if (opcode == 0x49)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR #", operand);
            eor(constant_u8(operand));
        }
        else if (opcode == 0x4a)
        {
            disassemble1(ct_pc, "LSR A");
            register_op(&FunctionBuilder::lsr, a_);
        }
        else if (opcode == 0x4b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_jmp_abs)
        {
            uint16_t operand;
            disassemble3(ct_pc, "JMP ", operand);
            pending_.insert(operand);
            control_transfer_to(constant_u16(operand), opcode);
        }
        else if (opcode == 0x4d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "EOR ", operand);
            eor(memory_read(abs(operand)));
        }
        else if (opcode == 0x4e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LSR ", operand);
            memory_op(&FunctionBuilder::lsr, abs(operand), ct_pc);
        }
        else if (opcode == 0x4f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bvc)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BVC ", target);
            pending_.insert(target);
            branch(flag_v_, false, target);
        }
        else if (opcode == 0x51)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR (", operand, "),Y");
            eor(memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0x52)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR (", operand, ")");
            eor(memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0x53)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x54)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x55)
        {
            uint8_t operand;
            disassemble2(ct_pc, "EOR ", operand, ",X");
            eor(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x56)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LSR ", operand, ",X");
            memory_op(&FunctionBuilder::lsr, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0x57)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x58)
        {
            disassemble1(ct_pc, "CLI");
            register_store(constant_jb(jit_bool_false), flag_i_);
        }
        else if (opcode == 0x59)
        {
            uint16_t operand;
            disassemble3(ct_pc, "EOR ", operand, ",Y");
            eor(memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0x5a)
        {
            disassemble1(ct_pc, "PHY");
            push_u8(register_load(y_), ct_pc);
        }
        else if (opcode == 0x5b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x5c)
        {
            illegal_instruction(ct_pc, 3);
        }
        else if (opcode == 0x5d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "EOR ", operand, ",X");
            eor(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0x5e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LSR ", operand, ",X");
            memory_op(
                &FunctionBuilder::lsr, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0x5f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_rts)
        {
            disassemble1(ct_pc, "RTS");
            llvm::Value *new_pc = check_predicted_rts(original_ct_pc);
            control_transfer_to(new_pc, opcode);
        }
        else if (opcode == 0x61)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC (", operand, ",X)");
            adc(memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x62)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x63)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x64)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STZ ", operand);
            memory_write(zp(operand), constant_u8(0), ct_pc);
        }
        else if (opcode == 0x65)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC ", operand);
            adc(memory_read(zp(operand)));
        }
        else if (opcode == 0x66)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ROR ", operand);
            memory_op(&FunctionBuilder::ror, zp(operand), ct_pc);
        }
        else if (opcode == 0x67)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x68)
        {
            disassemble1(ct_pc, "PLA");
            llvm::Value *data = pop_u8();
            register_store(data, a_);
            set_nz(data);
        }
        else if (opcode == 0x69)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC #", operand);
            adc(constant_u8(operand));
        }
        else if (opcode == 0x6a)
        {
            disassemble1(ct_pc, "ROR A");
            register_op(&FunctionBuilder::ror, a_);
        }
        else if (opcode == 0x6b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_jmp_ind_abs)
        {
            uint16_t operand;
            disassemble3(ct_pc, "JMP (", operand, ")");
            llvm::Value *low_byte = memory_read_untrapped(abs(operand));
            // We're emulating the 65C02 here so we don't wrap if operand
            // is of the form &xxFF. (Unless xx is FF, of course.)
            uint16_t high_byte_at = operand + 1;
            llvm::Value *high_byte = memory_read_untrapped(abs(high_byte_at));
            llvm::Value *new_pc = create_u16(low_byte, high_byte);
            control_transfer_to(new_pc, opcode);
        }
        else if (opcode == 0x6d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ADC ", operand);
            adc(memory_read(abs(operand)));
        }
        else if (opcode == 0x6e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ROR ", operand);
            memory_op(&FunctionBuilder::ror, abs(operand), ct_pc);
        }
        else if (opcode == 0x6f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bvs)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BVS ", target);
            pending_.insert(target);
            branch(flag_v_, true, target);
        }
        else if (opcode == 0x71)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC (", operand, "),Y");
            adc(memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0x72)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC (", operand, ")");
            adc(memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0x73)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x74)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STZ ", operand, ",X");
            memory_write(zp_index(constant_u8(operand), register_load(x_)), 
                         constant_u8(0), ct_pc);
        }
        else if (opcode == 0x75)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ADC ", operand, ",X");
            adc(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0x76)
        {
            uint8_t operand;
            disassemble2(ct_pc, "ROR ", operand, ",X");
            memory_op(&FunctionBuilder::ror, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0x77)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x78)
        {
            disassemble1(ct_pc, "SEI");
            register_store(constant_jb(jit_bool_true), flag_i_);
        }
        else if (opcode == 0x79)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ADC ", operand, ",Y");
            adc(memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0x7a)
        {
            disassemble1(ct_pc, "PLY");
            llvm::Value *data = pop_u8();
            register_store(data, y_);
            set_nz(data);
        }
        else if (opcode == 0x7b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_jmp_indx_abs)
        {
            uint16_t operand;
            disassemble3(ct_pc, "JMP (", operand, ",X)");
            llvm::Value *low_byte_at = 
                builder_.CreateAdd(
                    constant_u16(operand), 
                    zext_i16(register_load(x_)));
            llvm::Value *high_byte_at = 
                builder_.CreateAdd(low_byte_at, constant_u16(1));
            llvm::Value *low_byte = 
                memory_read_untrapped(BoundedAddress(*this, low_byte_at));
            llvm::Value *high_byte = 
                memory_read_untrapped(BoundedAddress(*this, high_byte_at));
            llvm::Value *new_pc = create_u16(low_byte, high_byte);
            control_transfer_to(new_pc, opcode);
        }
        else if (opcode == 0x7d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ADC ", operand, ",X");
            adc(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0x7e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "ROR ", operand, ",X");
            memory_op(
                &FunctionBuilder::ror, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0x7f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bra)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BRA ", target);
            pending_.insert(target);
            control_transfer_to(constant_u16(target), opcode);
        }
        else if (opcode == 0x81)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STA (", operand, ",X)");
            memory_write(zp_pre_index(constant_u8(operand), register_load(x_)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x82)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0x83)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x84)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STY ", operand);
            memory_write(zp(operand), register_load(y_), ct_pc);
        }
        else if (opcode == 0x85)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STA ", operand);
            memory_write(zp(operand), register_load(a_), ct_pc);
        }
        else if (opcode == 0x86)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STX ", operand);
            memory_write(zp(operand), register_load(x_), ct_pc);
        }
        else if (opcode == 0x87)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x88)
        {
            disassemble1(ct_pc, "DEY");
            register_op(&FunctionBuilder::dec, y_);
        }
        else if (opcode == 0x89)
        {
            uint8_t operand;
            disassemble2(ct_pc, "BIT #", operand);
            // Note that unlike other BIT opcodes, this one only affects
            // the Z flag.
            llvm::Value *tmp = 
                builder_.CreateAnd(register_load(a_), constant_u8(operand));
            set_z(tmp);
        }
        else if (opcode == 0x8a)
        {
            disassemble1(ct_pc, "TXA");
            transfer(x_, a_);
        }
        else if (opcode == 0x8b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x8c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STY ", operand);
            memory_write(abs(operand), register_load(y_), ct_pc);
        }
        else if (opcode == 0x8d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STA ", operand);
            memory_write(abs(operand), register_load(a_), ct_pc);
        }
        else if (opcode == 0x8e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STX ", operand);
            memory_write(abs(operand), register_load(x_), ct_pc);
        }
        else if (opcode == 0x8f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bcc)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BCC ", target);
            pending_.insert(target);
            branch(flag_c_, false, target);
        }
        else if (opcode == 0x91)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STA (", operand, "),Y");
            memory_write(zp_post_index(constant_u8(operand), register_load(y_)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x92)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STA (", operand, ")");
            memory_write(zp_post_index(constant_u8(operand), constant_u8(0)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x93)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x94)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STY ", operand, ",X");
            memory_write(zp_index(constant_u8(operand), register_load(x_)), 
                         register_load(y_), ct_pc);
        }
        else if (opcode == 0x95)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STA ", operand, ",X");
            memory_write(zp_index(constant_u8(operand), register_load(x_)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x96)
        {
            uint8_t operand;
            disassemble2(ct_pc, "STX ", operand, ",Y");
            memory_write(zp_index(constant_u8(operand), register_load(y_)), 
                         register_load(x_), ct_pc);
        }
        else if (opcode == 0x97)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x98)
        {
            disassemble1(ct_pc, "TYA");
            transfer(y_, a_);
        }
        else if (opcode == 0x99)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STA ", operand, ",Y");
            memory_write(abs_index(constant_u16(operand), register_load(y_)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x9a)
        {
            disassemble1(ct_pc, "TXS");
            // We don't use transfer() even though we do for TSX; TXS doesn't
            // set any flags.
            register_store(register_load(x_), s_);
        }
        else if (opcode == 0x9b)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0x9c)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STZ ", operand);
            memory_write(abs(operand), constant_u8(0), ct_pc);
        }
        else if (opcode == 0x9d)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STA ", operand, ",X");
            memory_write(abs_index(constant_u16(operand), register_load(x_)), 
                         register_load(a_), ct_pc);
        }
        else if (opcode == 0x9e)
        {
            uint16_t operand;
            disassemble3(ct_pc, "STZ ", operand, ",X");
            memory_write(abs_index(constant_u16(operand), register_load(x_)), 
                         constant_u8(0), ct_pc);
        }
        else if (opcode == 0x9f)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xa0)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDY #", operand);
            ld(y_, constant_u8(operand));
        }
        else if (opcode == 0xa1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA (", operand, ",X)");
            ld(a_, memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xa2)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDX #", operand);
            ld(x_, constant_u8(operand));
        }
        else if (opcode == 0xa3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xa4)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDY ", operand);
            ld(y_, memory_read(zp(operand)));
        }
        else if (opcode == 0xa5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA ", operand);
            ld(a_, memory_read(zp(operand)));
        }
        else if (opcode == 0xa6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDX ", operand);
            ld(x_, memory_read(zp(operand)));
        }
        else if (opcode == 0xa7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xa8)
        {
            disassemble1(ct_pc, "TAY");
            transfer(a_, y_);
        }
        else if (opcode == 0xa9)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA #", operand);
            ld(a_, constant_u8(operand));
        }
        else if (opcode == 0xaa)
        {
            disassemble1(ct_pc, "TAX");
            transfer(a_, x_);
        }
        else if (opcode == 0xab)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xac)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDY ", operand);
            ld(y_, memory_read(abs(operand)));
        }
        else if (opcode == 0xad)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDA ", operand);
            ld(a_, memory_read(abs(operand)));
        }
        else if (opcode == 0xae)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDX ", operand);
            ld(x_, memory_read(abs(operand)));
        }
        else if (opcode == 0xaf)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bcs)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BCS ", target);
            pending_.insert(target);
            branch(flag_c_, true, target);
        }
        else if (opcode == 0xb1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA (", operand, "),Y");
            ld(a_, memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0xb2)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA (", operand, ")");
            ld(a_, memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0xb3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xb4)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDY ", operand, ",X");
            ld(y_, memory_read(
                zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xb5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDA ", operand, ",X");
            ld(a_, memory_read(
                zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xb6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "LDX ", operand, ",Y");
            ld(x_, memory_read(
                zp_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0xb7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xb8)
        {
            disassemble1(ct_pc, "CLV");
            register_store(constant_jb(jit_bool_false), flag_v_);
        }
        else if (opcode == 0xb9)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDA ", operand, ",Y");
            ld(a_, memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0xba)
        {
            disassemble1(ct_pc, "TSX");
            transfer(s_, x_);
        }
        else if (opcode == 0xbb)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xbc)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDY ", operand, ",X");
            ld(y_, memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0xbd)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDA ", operand, ",X");
            ld(a_, memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0xbe)
        {
            uint16_t operand;
            disassemble3(ct_pc, "LDX ", operand, ",Y");
            ld(x_, memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0xbf)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xc0)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CPY #", operand);
            cmp(register_load(y_), constant_u8(operand));
        }
        else if (opcode == 0xc1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP (", operand, ",X)");
            cmp(register_load(a_), 
                memory_read(
                    zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xc2)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0xc3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xc4)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CPY ", operand);
            cmp(register_load(y_), memory_read(zp(operand)));
        }
        else if (opcode == 0xc5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP ", operand);
            cmp(register_load(a_), memory_read(zp(operand)));
        }
        else if (opcode == 0xc6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "DEC ", operand);
            memory_op(&FunctionBuilder::dec, zp(operand), ct_pc);
        }
        else if (opcode == 0xc7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xc8)
        {
            disassemble1(ct_pc, "INY");
            register_op(&FunctionBuilder::inc, y_);
        }
        else if (opcode == 0xc9)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP #", operand);
            cmp(register_load(a_), constant_u8(operand));
        }
        else if (opcode == 0xca)
        {
            disassemble1(ct_pc, "DEX");
            register_op(&FunctionBuilder::dec, x_);
        }
        else if (opcode == 0xcb)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xcc)
        {
            uint16_t operand;
            disassemble3(ct_pc, "CPY ", operand);
            cmp(register_load(y_), memory_read(abs(operand)));
        }
        else if (opcode == 0xcd)
        {
            uint16_t operand;
            disassemble3(ct_pc, "CMP ", operand);
            cmp(register_load(a_), memory_read(abs(operand)));
        }
        else if (opcode == 0xce)
        {
            uint16_t operand;
            disassemble3(ct_pc, "DEC ", operand);
            memory_op(&FunctionBuilder::dec, abs(operand), ct_pc);
        }
        else if (opcode == 0xcf)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_bne)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BNE ", target);
            pending_.insert(target);
            branch(flag_z_, false, target);
        }
        else if (opcode == 0xd1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP (", operand, "),Y");
            cmp(register_load(a_), 
                memory_read(
                    zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0xd2)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP (", operand, ")");
            cmp(register_load(a_), 
                memory_read(
                    zp_post_index(constant_u8(operand), constant_u8(0))));
        } 
        else if (opcode == 0xd3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xd4)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0xd5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CMP ", operand, ",X");
            cmp(register_load(a_), 
                memory_read(
                    zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xd6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "DEC ", operand, ",X");
            memory_op(&FunctionBuilder::dec, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0xd7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xd8)
        {
            disassemble1(ct_pc, "CLD");
            register_store(constant_jb(jit_bool_false), flag_d_);
        }
        else if (opcode == 0xd9)
        {
            uint16_t operand;
            disassemble3(ct_pc, "CMP ", operand, ",Y");
            cmp(register_load(a_), 
                memory_read(
                    abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0xda)
        {
            disassemble1(ct_pc, "PHX");
            push_u8(register_load(x_), ct_pc);
        }
        else if (opcode == 0xdb)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xdc)
        {
            illegal_instruction(ct_pc, 3);
        }
        else if (opcode == 0xdd)
        {
            uint16_t operand;
            disassemble3(ct_pc, "CMP ", operand, ",X");
            cmp(register_load(a_), 
                memory_read(
                    abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0xde)
        {
            uint16_t operand;
            disassemble3(ct_pc, "DEC ", operand, ",X");
            memory_op(
                &FunctionBuilder::dec, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0xdf)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xe0)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CPX #", operand);
            cmp(register_load(x_), constant_u8(operand));
        }
        else if (opcode == 0xe1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC (", operand, ",X)");
            sbc(memory_read(
                zp_pre_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xe2)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0xe3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xe4)
        {
            uint8_t operand;
            disassemble2(ct_pc, "CPX ", operand);
            cmp(register_load(x_), memory_read(zp(operand)));
        }
        else if (opcode == 0xe5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC ", operand);
            sbc(memory_read(zp(operand)));
        }
        else if (opcode == 0xe6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "INC ", operand);
            memory_op(&FunctionBuilder::inc, zp(operand), ct_pc);
        }
        else if (opcode == 0xe7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xe8)
        {
            disassemble1(ct_pc, "INX");
            register_op(&FunctionBuilder::inc, x_);
        }
        else if (opcode == 0xe9)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC #", operand);
            sbc(constant_u8(operand));
        }
        else if (opcode == 0xea)
        {
            disassemble1(ct_pc, "NOP");
        }
        else if (opcode == 0xeb)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xec)
        {
            uint16_t operand;
            disassemble3(ct_pc, "CPX ", operand);
            cmp(register_load(x_), memory_read(abs(operand)));
        }
        else if (opcode == 0xed)
        {
            uint16_t operand;
            disassemble3(ct_pc, "SBC ", operand);
            sbc(memory_read(abs(operand)));
        }
        else if (opcode == 0xee)
        {
            uint16_t operand;
            disassemble3(ct_pc, "INC ", operand);
            memory_op(&FunctionBuilder::inc, abs(operand), ct_pc);
        }
        else if (opcode == 0xef)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == opcode_beq)
        {
            uint16_t target;
            disassemble_branch(ct_pc, "BEQ ", target);
            pending_.insert(target);
            branch(flag_z_, true, target);
        }
        else if (opcode == 0xf1)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC (", operand, "),Y");
            sbc(memory_read(
                zp_post_index(constant_u8(operand), register_load(y_))));
        }
        else if (opcode == 0xf2)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC (", operand, ")");
            sbc(memory_read(
                zp_post_index(constant_u8(operand), constant_u8(0))));
        }
        else if (opcode == 0xf3)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xf4)
        {
            illegal_instruction(ct_pc, 2);
        }
        else if (opcode == 0xf5)
        {
            uint8_t operand;
            disassemble2(ct_pc, "SBC ", operand, ",X");
            sbc(memory_read(zp_index(constant_u8(operand), register_load(x_))));
        }
        else if (opcode == 0xf6)
        {
            uint8_t operand;
            disassemble2(ct_pc, "INC ", operand, ",X");
            memory_op(&FunctionBuilder::inc, 
                      zp_index(constant_u8(operand), register_load(x_)), ct_pc);
        }
        else if (opcode == 0xf7)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xf8)
        {
            disassemble1(ct_pc, "SED");
            register_store(constant_jb(jit_bool_true), flag_d_);
        }
        else if (opcode == 0xf9)
        {
            uint16_t operand;
            disassemble3(ct_pc, "SBC ", operand, ",Y");
            sbc(memory_read(
                abs_index(constant_u16(operand), register_load(y_))));
        }
        else if (opcode == 0xfa)
        {
            disassemble1(ct_pc, "PLX");
            llvm::Value *data = pop_u8();
            register_store(data, x_);
            set_nz(data);
        }
        else if (opcode == 0xfb)
        {
            illegal_instruction(ct_pc, 1);
        }
        else if (opcode == 0xfc)
        {
            illegal_instruction(ct_pc, 3);
        }
        else if (opcode == 0xfd)
        {
            uint16_t operand;
            disassemble3(ct_pc, "SBC ", operand, ",X");
            sbc(memory_read(
                abs_index(constant_u16(operand), register_load(x_))));
        }
        else if (opcode == 0xfe)
        {
            uint16_t operand;
            disassemble3(ct_pc, "INC ", operand, ",X");
            memory_op(
                &FunctionBuilder::inc, 
                abs_index(constant_u16(operand), register_load(x_)), 
                ct_pc);
        }
        else if (opcode == 0xff)
        {
            illegal_instruction(ct_pc, 1);
        }
        else
        {
            CANT_HAPPEN("Unknown opcode 0x" << std::hex << opcode);
        }
    }

    return ct_pc;
}

// Return the 8-bit operand of the instruction whose opcode is located at
// the given address.
uint8_t FunctionBuilder::operand8(uint16_t opcode_at)
{
    uint16_t addr = opcode_at;
    return ct_memory_[++addr];
}

// Return the 16-bit operand of the instruction whose opcode is located at
// the given address.
uint16_t FunctionBuilder::operand16(uint16_t opcode_at)
{
    uint16_t addr = opcode_at;
    uint8_t operand_low = ct_memory_[++addr];
    uint8_t operand_high = ct_memory_[++addr];
    return operand_low | (operand_high << 8);
} 

llvm::Value *FunctionBuilder::constant_i1(bool c)
{
    return llvm::ConstantInt::get(i1_type_, c);
}

llvm::Value *FunctionBuilder::constant_u8(uint8_t c)
{
    return llvm::ConstantInt::get(i8_type_, c);
}

llvm::Value *FunctionBuilder::constant_u16(uint16_t c)
{
    return llvm::ConstantInt::get(i16_type_, c);
}

llvm::Value *FunctionBuilder::constant_u32(uint32_t c)
{
    return llvm::ConstantInt::get(i32_type_, c);
}

llvm::Value *FunctionBuilder::constant_u64(uint64_t c)
{
    return llvm::ConstantInt::get(i64_type_, c);
}

llvm::Value *FunctionBuilder::constant_i(int c)
{
    return llvm::ConstantInt::get(native_int_type_, c);
}

llvm::Value *FunctionBuilder::constant_jb(JitBool c)
{
    return llvm::ConstantInt::get(jit_bool_type_, c);
}

llvm::Value *FunctionBuilder::convert_i1_to_jb(llvm::Value *v)
{
    assert(v->getType() == i1_type_);
    return builder_.CreateZExt(v, jit_bool_type_);
}

llvm::Value *FunctionBuilder::convert_i8_to_jb(llvm::Value *v)
{
    assert(v->getType() == i8_type_);
    return v;
}

llvm::Value *FunctionBuilder::convert_i16_to_jb(llvm::Value *v)
{
    assert(v->getType() == i16_type_);
    return convert_i1_to_jb(builder_.CreateICmpNE(v, constant_u16(0)));
}

// JitBool values should be tested via jit_bool_is_*() and not directly;
// this is because they use a 0=false, non-0=true representation. It's not
// correct to assume they are either 0 or 1.

llvm::Value *FunctionBuilder::jit_bool_is_true(llvm::Value *v)
{
    assert(v->getType() == jit_bool_type_);
    return builder_.CreateICmpNE(v, constant_u8(0));
}

llvm::Value *FunctionBuilder::jit_bool_is_false(llvm::Value *v)
{
    assert(v->getType() == jit_bool_type_);
    return builder_.CreateICmpEQ(v, constant_u8(0));
}

llvm::Value *FunctionBuilder::convert_i1_to_i8(llvm::Value *v)
{
    assert(v->getType() == i1_type_);
    return builder_.CreateZExt(v, i8_type_);
}

llvm::Value *FunctionBuilder::zext_i16(llvm::Value *v)
{
    return builder_.CreateZExt(v, i16_type_);
}

llvm::Value *FunctionBuilder::zext_i32(llvm::Value *v)
{
    return builder_.CreateZExt(v, i32_type_);
}

llvm::Value *FunctionBuilder::sext_i16(llvm::Value *v)
{
    return builder_.CreateSExt(v, i16_type_);
}

llvm::Value *FunctionBuilder::trunc_i8(llvm::Value *v)
{
    return builder_.CreateTrunc(v, i8_type_);
}

llvm::Value *FunctionBuilder::create_u16(
    llvm::Value *low_byte, llvm::Value *high_byte)
{
    return builder_.CreateOr(
        zext_i16(low_byte), 
        builder_.CreateShl(zext_i16(high_byte), 8));
}

llvm::Value *FunctionBuilder::register_load(const Register &r)
{
    return builder_.CreateLoad(r.v_);
}

void FunctionBuilder::register_store(llvm::Value *v, Register &r)
{
    builder_.CreateStore(v, r.v_);
    r.modified_ = true;
}

void FunctionBuilder::register_op(OpFn op, Register &r)
{
    llvm::Value *data = register_load(r);
    data = (this->*op)(data);
    register_store(data, r);
}

void FunctionBuilder::memory_op(
    OpFn op, const BoundedAddress &ba, uint16_t next_opcode_at)
{
    llvm::Value *data = memory_read(ba);
    data = (this->*op)(data);
    memory_write(ba, data, next_opcode_at);
}

void FunctionBuilder::adc(llvm::Value *data)
{
    llvm::BasicBlock *done_adc_block = 
        llvm::BasicBlock::Create(context_, "done_adc");
    llvm::BasicBlock *adc_binary_block = 
        llvm::BasicBlock::Create(context_, "adc_binary", llvm_function_);
    llvm::BasicBlock *adc_decimal_block = 
        llvm::BasicBlock::Create(context_, "adc_decimal", llvm_function_);
    llvm::Value *d_clear = jit_bool_is_false(register_load(flag_d_));
    builder_.CreateCondBr(d_clear, adc_binary_block, adc_decimal_block);
    llvm_function_->getBasicBlockList().push_back(done_adc_block);
    builder_.SetInsertPoint(adc_binary_block);
    adc_binary(data);
    builder_.CreateBr(done_adc_block);
    builder_.SetInsertPoint(adc_decimal_block);
    adc_decimal(data);
    builder_.CreateBr(done_adc_block);
    builder_.SetInsertPoint(done_adc_block);
}

void FunctionBuilder::adc_binary(llvm::Value *data)
{
    llvm::Value *carry_16 = zext_i16(jit_bool_is_true(register_load(flag_c_)));

    llvm::Value *a_u16 = zext_i16(register_load(a_));
    llvm::Value *data_u16 = zext_i16(data);
    llvm::Value *sum_u16 = 
        builder_.CreateAdd(builder_.CreateAdd(a_u16, data_u16), carry_16);

    llvm::Value *a_s16 = builder_.CreateSExt(register_load(a_), i16_type_);
    llvm::Value *data_s16 = builder_.CreateSExt(data, i16_type_);
    llvm::Value *sum_s16 = 
        builder_.CreateAdd(builder_.CreateAdd(a_s16, data_s16), carry_16);

    llvm::Value *new_a = trunc_i8(sum_u16);
    register_store(new_a, a_);
    set_nz(new_a);

    llvm::Value *b8 = builder_.CreateAnd(
        sum_u16, 
        constant_u16(0x100));
    register_store(convert_i16_to_jb(b8), flag_c_);

    llvm::Value *negative_as_unsigned = 
        jit_bool_is_true(register_load(flag_n_));
    llvm::Value *negative_as_signed = 
        builder_.CreateICmpSLT(sum_s16, constant_u16(0));
    llvm::Value *new_v_as_i1 =
        builder_.CreateXor(negative_as_unsigned, negative_as_signed);
    register_store(convert_i1_to_jb(new_v_as_i1), flag_v_);
}

void FunctionBuilder::adc_decimal(llvm::Value *data)
{
    // This algorithm taken from http://www.6502.org/tutorials/decimal_mode.html

    llvm::Value *carry = jit_bool_is_true(register_load(flag_c_));

    builder_.CreateStore(
        builder_.CreateAdd(
            builder_.CreateAdd(
                builder_.CreateAnd(
                    register_load(a_),
                    constant_u8(0x0f)),
                builder_.CreateAnd(
                    data,
                    constant_u8(0x0f))),
            convert_i1_to_i8(carry)),
        l_tmp_);

    llvm::BasicBlock *adjust_l_block = 
        llvm::BasicBlock::Create(context_, "adjust_l", llvm_function_);
    llvm::BasicBlock *l_done_block = 
        llvm::BasicBlock::Create(context_, "l_done", llvm_function_);
    builder_.CreateCondBr(
        builder_.CreateICmpUGE(
            builder_.CreateLoad(l_tmp_), 
            constant_u8(0x0a)),
        adjust_l_block, l_done_block);

    builder_.SetInsertPoint(adjust_l_block);
    builder_.CreateStore(
        builder_.CreateAdd(
            builder_.CreateAnd(
                builder_.CreateAdd(
                    builder_.CreateLoad(l_tmp_),
                    constant_u8(0x06)),
                constant_u8(0x0f)),
            constant_u8(0x10)),
        l_tmp_);
    builder_.CreateBr(l_done_block);

    builder_.SetInsertPoint(l_done_block);

    llvm::Value *a_and_0xf0 =
        builder_.CreateAnd(
            register_load(a_),
            constant_u8(0xf0));
    llvm::Value *data_and_0xf0 =
        builder_.CreateAnd(
            data,
            constant_u8(0xf0));

    builder_.CreateStore(
        builder_.CreateAdd(
            builder_.CreateAdd(
                zext_i16(a_and_0xf0),
                zext_i16(data_and_0xf0)),
            zext_i16(builder_.CreateLoad(l_tmp_))),
        s_tmp_);    

    llvm::BasicBlock *adjust_s_block = 
        llvm::BasicBlock::Create(context_, "adjust_s", llvm_function_);
    llvm::BasicBlock *s_done_block = 
        llvm::BasicBlock::Create(context_, "s_done", llvm_function_);
    builder_.CreateCondBr(
        builder_.CreateICmpUGE(
            builder_.CreateLoad(s_tmp_), 
            constant_u16(0xa0)),
        adjust_s_block, s_done_block);

    builder_.SetInsertPoint(adjust_s_block);
    builder_.CreateStore(
        builder_.CreateAdd(
            builder_.CreateLoad(s_tmp_),
            constant_u16(0x60)),
        s_tmp_);
    builder_.CreateBr(s_done_block);

    builder_.SetInsertPoint(s_done_block);
    builder_.CreateStore(
        builder_.CreateAdd(
            builder_.CreateAdd(
                sext_i16(a_and_0xf0),
                sext_i16(data_and_0xf0)),
            zext_i16(builder_.CreateLoad(l_tmp_))),
        t_tmp_);

    llvm::BasicBlock *v_not_done_block = 
        llvm::BasicBlock::Create(context_, "v_not_done", llvm_function_);
    llvm::BasicBlock *v_false_block = 
        llvm::BasicBlock::Create(context_, "v_false", llvm_function_);
    llvm::BasicBlock *v_done_block = 
        llvm::BasicBlock::Create(context_, "v_done", llvm_function_);
    register_store(constant_jb(jit_bool_true), flag_v_);
    builder_.CreateCondBr(
        builder_.CreateICmpSLT(
            builder_.CreateLoad(t_tmp_), 
            constant_u16(-128)),
        v_done_block, v_not_done_block);
    builder_.SetInsertPoint(v_not_done_block);
    builder_.CreateCondBr(
        builder_.CreateICmpSGT(
            builder_.CreateLoad(t_tmp_), 
            constant_u16(127)),
        v_done_block, v_false_block);
    builder_.SetInsertPoint(v_false_block);
    register_store(constant_jb(jit_bool_false), flag_v_);
    builder_.CreateBr(v_done_block);
    builder_.SetInsertPoint(v_done_block);

    register_store(trunc_i8(builder_.CreateLoad(s_tmp_)), a_);
    set_nz(register_load(a_));
    register_store(
        convert_i1_to_jb(
            builder_.CreateICmpUGE(
                builder_.CreateLoad(s_tmp_),
                constant_u16(0x100))),
        flag_c_);
}

void FunctionBuilder::And(llvm::Value *data)
{
    llvm::Value *result = builder_.CreateAnd(register_load(a_), data);
    register_store(result, a_);
    set_nz(result);
}

llvm::Value *FunctionBuilder::asl(llvm::Value *data)
{
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x80))), flag_c_);
    llvm::Value *result = builder_.CreateShl(data, 1);
    set_nz(result);
    return result;
}

void FunctionBuilder::bit(llvm::Value *data)
{
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x80))), flag_n_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x40))), flag_v_);
    llvm::Value *tmp = builder_.CreateAnd(register_load(a_), data);
    set_z(tmp);
}

void FunctionBuilder::branch(Register &flag, bool branch_if, uint16_t target)
{
    llvm::BasicBlock *not_taken_block = 
        llvm::BasicBlock::Create(context_, "branch_not_taken", llvm_function_);
    ensure_address_block_created(target);
    llvm::Value *flag_set = jit_bool_is_true(register_load(flag));
    if (branch_if)
    {
        builder_.CreateCondBr(flag_set, address_block_[target], 
                              not_taken_block);
    }
    else
    {
        builder_.CreateCondBr(flag_set, not_taken_block, 
                              address_block_[target]);
    }
    builder_.SetInsertPoint(not_taken_block);
}

void FunctionBuilder::cmp(llvm::Value *r, llvm::Value *data)
{
    llvm::Value *sum = builder_.CreateSub(r, data);
    set_nz(sum);
    register_store(convert_i1_to_jb(builder_.CreateICmpUGE(r, data)), flag_c_);
}

llvm::Value *FunctionBuilder::dec(llvm::Value *data)
{
    llvm::Value *result = builder_.CreateSub(data, constant_u8(1));
    set_nz(result);
    return result;
}

void FunctionBuilder::eor(llvm::Value *data)
{
    llvm::Value *result = builder_.CreateXor(register_load(a_), data);
    register_store(result, a_);
    set_nz(result);
}

llvm::Value *FunctionBuilder::inc(llvm::Value *data)
{
    llvm::Value *result = builder_.CreateAdd(data, constant_u8(1));
    set_nz(result);
    return result;
}

void FunctionBuilder::ld(Register &r, llvm::Value *data)
{
    register_store(data, r);
    set_nz(data);
}

llvm::Value *FunctionBuilder::lsr(llvm::Value *data)
{
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x1))), flag_c_);
    llvm::Value *result = builder_.CreateLShr(data, 1);
    set_nz(result);
    return result;
}

void FunctionBuilder::ora(llvm::Value *data)
{
    llvm::Value *result = builder_.CreateOr(register_load(a_), data);
    register_store(result, a_);
    set_nz(result);
}

void FunctionBuilder::pop_flags()
{
    llvm::Value *p = pop_u8();
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagN))), flag_n_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagV))), flag_v_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagD))), flag_d_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagI))), flag_i_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagZ))), flag_z_);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(p, constant_u8(flagC))), flag_c_);
}

llvm::Value *FunctionBuilder::pop_u8()
{
    llvm::Value *new_s = builder_.CreateAdd(register_load(s_), constant_u8(1));
    register_store(new_s, s_);
    return memory_read_untrapped(abs_index(constant_u16(stack), new_s));
}


llvm::Value *FunctionBuilder::pop_u16()
{
    llvm::Value *low_byte = pop_u8();
    llvm::Value *high_byte = pop_u8();
    return create_u16(low_byte, high_byte);
}

void FunctionBuilder::push_u8_raw(llvm::Value *data)
{
    memory_write_raw(abs_index(constant_u16(stack), register_load(s_)), data);
    register_store(builder_.CreateSub(register_load(s_), constant_u8(1)), s_);
}

void FunctionBuilder::push_u16_raw(uint16_t u)
{
    uint8_t high_byte = u >> 8;
    uint8_t low_byte = u & 0xff;
    push_u8_raw(constant_u8(high_byte));
    push_u8_raw(constant_u8(low_byte));
}

// Push the given value onto the stack.
//
// Note that because the push may invalidate code living on the stack,
// this may generate intructions which return control to the caller to
// deal with that, so within a given opcode being translated, no further
// code-generating functions should be called after this.
void FunctionBuilder::push_u8(llvm::Value *data, uint16_t next_opcode_at)
{
    llvm::Value *old_s = register_load(s_);
    const BoundedAddress &ba = abs_index(constant_u16(stack), old_s);
    register_store(builder_.CreateSub(old_s, constant_u8(1)), s_);
    memory_write_untrapped(ba, data, next_opcode_at);
}

llvm::Value *FunctionBuilder::rol(llvm::Value *data)
{
    llvm::Value *new_low_bit = 
        convert_i1_to_i8(jit_bool_is_true(register_load(flag_c_)));
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x80))), flag_c_);
    llvm::Value *result = 
        builder_.CreateOr(builder_.CreateShl(data, 1), new_low_bit);
    set_nz(result);
    return result;
}

llvm::Value *FunctionBuilder::ror(llvm::Value *data)
{
    llvm::Value *c_as_bit = 
        convert_i1_to_i8(jit_bool_is_true(register_load(flag_c_)));
    llvm::Value *new_high_bit = builder_.CreateShl(c_as_bit, 7);
    register_store(
        convert_i8_to_jb(builder_.CreateAnd(data, constant_u8(0x1))), flag_c_);
    llvm::Value *result = 
        builder_.CreateOr(builder_.CreateLShr(data, 1), new_high_bit);
    set_nz(result);
    return result;
}

void FunctionBuilder::sbc(llvm::Value *data)
{
    llvm::BasicBlock *done_sbc_block = 
        llvm::BasicBlock::Create(context_, "done_sbc");
    llvm::BasicBlock *sbc_binary_block = 
        llvm::BasicBlock::Create(context_, "sbc_binary", llvm_function_);
    llvm::BasicBlock *sbc_decimal_block = 
        llvm::BasicBlock::Create(context_, "sbc_decimal", llvm_function_);
    llvm::Value *d_clear = jit_bool_is_false(register_load(flag_d_));
    builder_.CreateCondBr(d_clear, sbc_binary_block, sbc_decimal_block);
    llvm_function_->getBasicBlockList().push_back(done_sbc_block);
    builder_.SetInsertPoint(sbc_binary_block);
    sbc_binary(data);
    builder_.CreateBr(done_sbc_block);
    builder_.SetInsertPoint(sbc_decimal_block);
    sbc_decimal(data);
    builder_.CreateBr(done_sbc_block);
    builder_.SetInsertPoint(done_sbc_block);
}

void FunctionBuilder::sbc_binary(llvm::Value *data)
{
    llvm::Value *borrow_16 = 
        zext_i16(jit_bool_is_false(register_load(flag_c_)));

    sbc_overflow(data, borrow_16); // must do this before storing new value to a

    llvm::Value *a_u16 = zext_i16(register_load(a_));
    llvm::Value *data_u16 = zext_i16(data);
    llvm::Value *result_u16 = 
        builder_.CreateSub(builder_.CreateSub(a_u16, data_u16), borrow_16);

    llvm::Value *new_a = trunc_i8(result_u16);
    register_store(new_a, a_);
    set_nz(new_a);

    register_store(
        convert_i1_to_jb(
            builder_.CreateICmpEQ(
                builder_.CreateAnd(result_u16, constant_u16(0x100)),
                constant_u16(0))),
        flag_c_);
}

void FunctionBuilder::sbc_decimal(llvm::Value *data)
{
    llvm::Value *borrow = jit_bool_is_false(register_load(flag_c_));
    llvm::Value *borrow_16 = zext_i16(borrow);

    sbc_overflow(data, borrow_16); // must do this before modifying a

    builder_.CreateStore(
        builder_.CreateSub(
            builder_.CreateSub(
                builder_.CreateAnd(
                    register_load(a_),
                    constant_u8(0x0f)),
                builder_.CreateAnd(
                    data,
                    constant_u8(0x0f))),
            convert_i1_to_i8(borrow)),
        l_tmp_);

    builder_.CreateStore(
        builder_.CreateSub(
            builder_.CreateSub(
                zext_i16(register_load(a_)),
                zext_i16(data)),
            borrow_16),
        s_tmp_);

    register_store(
        convert_i1_to_jb(
            builder_.CreateICmpEQ(
                builder_.CreateAnd(
                    builder_.CreateLoad(s_tmp_),
                    constant_u16(0x100)),
                constant_u16(0))),
        flag_c_);

    llvm::BasicBlock *s_adjust1_block = 
        llvm::BasicBlock::Create(context_, "s_adjust1", llvm_function_);
    llvm::BasicBlock *done_s_adjust1_block = 
        llvm::BasicBlock::Create(context_, "done_s_adjust1", llvm_function_);
    builder_.CreateCondBr(
        builder_.CreateICmpSLT(
            builder_.CreateLoad(s_tmp_),
            constant_u16(0)),
        s_adjust1_block,
        done_s_adjust1_block);

    builder_.SetInsertPoint(s_adjust1_block);
    builder_.CreateStore(
        builder_.CreateSub(
            builder_.CreateLoad(s_tmp_),
            constant_u16(0x60)),
        s_tmp_);
    builder_.CreateBr(done_s_adjust1_block);

    builder_.SetInsertPoint(done_s_adjust1_block);

    llvm::BasicBlock *s_adjust2_block = 
        llvm::BasicBlock::Create(context_, "s_adjust2", llvm_function_);
    llvm::BasicBlock *done_s_adjust2_block = 
        llvm::BasicBlock::Create(context_, "done_s_adjust2", llvm_function_);
    builder_.CreateCondBr(
        builder_.CreateICmpSLT(
            builder_.CreateLoad(l_tmp_),
            constant_u8(0)),
        s_adjust2_block,
        done_s_adjust2_block);

    builder_.SetInsertPoint(s_adjust2_block);
    builder_.CreateStore(
        builder_.CreateSub(
            builder_.CreateLoad(s_tmp_),
            constant_u16(0x06)),
        s_tmp_);
    builder_.CreateBr(done_s_adjust2_block);

    builder_.SetInsertPoint(done_s_adjust2_block);
    register_store(trunc_i8(builder_.CreateLoad(s_tmp_)), a_);
    set_nz(register_load(a_));
}

void FunctionBuilder::sbc_overflow(
    llvm::Value *data, llvm::Value *borrow_16)
{
    llvm::Value *a_s16 = sext_i16(register_load(a_));
    llvm::Value *data_s16 = sext_i16(data);
    llvm::Value *result_s16 = 
        builder_.CreateSub(builder_.CreateSub(a_s16, data_s16), borrow_16);

    llvm::Value *negative_as_unsigned = 
        builder_.CreateICmpNE(
            builder_.CreateAnd(result_s16, constant_u16(0x80)),
            constant_u16(0));
    llvm::Value *negative_as_signed =
        builder_.CreateICmpSLT(result_s16, constant_u16(0));

    register_store(
        convert_i1_to_jb(
            builder_.CreateXor(negative_as_unsigned, negative_as_signed)),
        flag_v_);
}

void FunctionBuilder::transfer(
    const Register &from, Register &to)
{
    llvm::Value *data = builder_.CreateLoad(from.v_);
    register_store(data, to);
    set_nz(data);
}

llvm::Value *FunctionBuilder::trb(llvm::Value *data)
{
    set_z(builder_.CreateAnd(data, register_load(a_)));

    llvm::Value *result =
        builder_.CreateAnd(
            data,
            builder_.CreateXor(
                register_load(a_),
                constant_u8(0xff)));
    return result;
}

llvm::Value *FunctionBuilder::tsb(llvm::Value *data)
{
    set_z(builder_.CreateAnd(data, register_load(a_)));

    llvm::Value *result =
        builder_.CreateOr(
            data,
            register_load(a_));
    return result;
}

void FunctionBuilder::set_nz(llvm::Value *data)
{
    register_store(convert_i8_to_jb(builder_.CreateAnd(data, 0x80)), flag_n_);
    set_z(data);
}

void FunctionBuilder::set_z(llvm::Value *data)
{
    register_store(
        convert_i1_to_jb(builder_.CreateICmpEQ(data, constant_u8(0))), flag_z_);
}

llvm::Value *FunctionBuilder::flag_byte()
{
    builder_.CreateStore(constant_u8(0), p_tmp_);

    flag_byte_bit(flag_n_, flagN);
    flag_byte_bit(flag_v_, flagV);
    flag_byte_bit(flag_d_, flagD);
    flag_byte_bit(flag_i_, flagI);
    flag_byte_bit(flag_z_, flagZ);
    flag_byte_bit(flag_c_, flagC);

    return builder_.CreateLoad(p_tmp_);
}

void FunctionBuilder::flag_byte_bit(const Register &flag_reg, uint8_t flag_bit)
{
    llvm::BasicBlock *bit_set_block = 
        llvm::BasicBlock::Create(context_, "bit_set", llvm_function_);
    llvm::BasicBlock *bit_done_block = 
        llvm::BasicBlock::Create(context_, "bit_done", llvm_function_);
    llvm::Value *bit_set = jit_bool_is_true(register_load(flag_reg));
    builder_.CreateCondBr(bit_set, bit_set_block, bit_done_block);

    builder_.SetInsertPoint(bit_set_block);
    builder_.CreateStore(
        builder_.CreateOr(builder_.CreateLoad(p_tmp_), flag_bit), p_tmp_);
    builder_.CreateBr(bit_done_block);

    builder_.SetInsertPoint(bit_done_block);
}

void FunctionBuilder::illegal_instruction(uint16_t &ct_pc, int bytes)
{
    uint16_t opcode_at = ct_pc;
    uint8_t opcode = ct_memory_[opcode_at];

    std::stringstream s;
    s << "illegal " << hex_prefix << std::hex << std::setw(2) << 
         std::setfill('0') << static_cast<int>(opcode) << " ";
    switch (bytes)
    {
        case 1:
            disassemble1(ct_pc, s.str());
            break;

        case 2:
        {
            uint8_t operand;
            disassemble2(ct_pc, s.str(), operand);
            break;
        }

        case 3:
        {
            uint16_t operand;
            disassemble3(ct_pc, s.str(), operand);
            break;
        }

        default:
            CANT_HAPPEN("Invalid byte count (ct_pc 0x" << std::hex << ct_pc << 
                        ", " << std::dec << "bytes " << bytes << ")");
    }

    if (callbacks_.illegal_instruction[opcode] != 0)
    {
        return_illegal_instruction(ct_pc, opcode_at, opcode);
    }
    else
    {
        // Illegal instructions are defined on the 65C02 to be no-ops.
    }
}

FunctionBuilder::BoundedAddress FunctionBuilder::zp(uint8_t addr)
{
    // We still generate a u16 for the actual llvm::Value. It probably doesn't
    // make any difference but it seems logical as memory address "are" 16 bits,
    // even if 8-bit ones are handled more efficiently on a real 6502.
    return BoundedAddress(*this, constant_u16(addr), AddressRange(addr));
}

FunctionBuilder::BoundedAddress FunctionBuilder::abs(uint16_t addr)
{
    return BoundedAddress(*this, constant_u16(addr), AddressRange(addr));
}

FunctionBuilder::BoundedAddress FunctionBuilder::abs_index(
    llvm::Value *abs, llvm::Value *index)
{
    assert(abs->getType() == i16_type_);
    assert(index->getType() == i8_type_);

    llvm::ConstantInt *abs_ci = llvm::cast<llvm::ConstantInt>(abs);
    uint16_t range_begin = abs_ci->getLimitedValue();
    uint32_t range_end = range_begin;
    range_end += 0x100;

    return BoundedAddress(*this, builder_.CreateAdd(abs, zext_i16(index)), 
                          AddressRange(range_begin, range_end));
}

FunctionBuilder::BoundedAddress FunctionBuilder::zp_index(
    llvm::Value *zp, llvm::Value *index)
{
    assert(zp->getType() == i8_type_);
    assert(index->getType() == i8_type_);

    return BoundedAddress(*this, zext_i16(builder_.CreateAdd(zp, index)), 
                          AddressRange(0, 0x100));
}

FunctionBuilder::BoundedAddress FunctionBuilder::zp_post_index(
    llvm::Value *zp, llvm::Value *index)
{
    assert(zp->getType() == i8_type_);
    assert(index->getType() == i8_type_);

    llvm::Value *low_byte = 
        memory_read_untrapped(BoundedAddress(*this, zext_i16(zp)));
    llvm::Value *high_byte_at = builder_.CreateAdd(zp, constant_u8(1));
    llvm::Value *high_byte = 
        memory_read_untrapped(BoundedAddress(*this, zext_i16(high_byte_at)));
    llvm::Value *base_addr = create_u16(low_byte, high_byte);
    return BoundedAddress(*this, 
                          builder_.CreateAdd(base_addr, zext_i16(index)));
}

FunctionBuilder::BoundedAddress FunctionBuilder::zp_pre_index(
    llvm::Value *zp, llvm::Value *index)
{
    assert(zp->getType() == i8_type_);
    assert(index->getType() == i8_type_);

    llvm::Value *low_byte_at = builder_.CreateAdd(zp, index);
    llvm::Value *high_byte_at = builder_.CreateAdd(low_byte_at, constant_u8(1));
    llvm::Value *low_byte = 
        memory_read_untrapped(BoundedAddress(*this, zext_i16(low_byte_at)));
    llvm::Value *high_byte = 
        memory_read_untrapped(BoundedAddress(*this, zext_i16(high_byte_at)));
    return BoundedAddress(*this, create_u16(low_byte, high_byte));
}

llvm::Value *FunctionBuilder::check_predicted_rts(uint16_t subroutine_addr)
{
    llvm::Value *mangled_pc = pop_u16();
    llvm::Value *new_pc = builder_.CreateAdd(mangled_pc, constant_u16(1));

    // It would be correct to just return new_pc at this point; our caller
    // will use it to arrange a control transfer. Since that is a run-time
    // determined value, the control transfer would have to be done by
    // returning from the generated function. We may be able to make some
    // plausible guesses (currently never guaranteed to be correct) which
    // we can verify at run time and which if correct allow the RTS to be
    // handled as a branch within the generated function. This should save
    // a bit of overhead on not returning from the function and re-entering
    // another and may also allow the optimiser some additional leeway.

    const AddressSet &targets = predicted_rts_targets_[subroutine_addr];
    TRACE("Generating predicted RTS code; " << targets.size() << " target(s)");
    for (AddressSet::const_iterator it = targets.begin(); it != targets.end(); 
         ++it)
    {
        const uint16_t target = *it;
        llvm::BasicBlock *prediction_correct = 
            llvm::BasicBlock::Create(context_, "prediction_correct", 
                                     llvm_function_);
        llvm::BasicBlock *prediction_incorrect = 
            llvm::BasicBlock::Create(context_, "prediction_incorrect", 
                                     llvm_function_);
        builder_.CreateCondBr(
            builder_.CreateICmpEQ(constant_u16(target), new_pc), 
            prediction_correct, prediction_incorrect);
        builder_.SetInsertPoint(prediction_correct);
        control_transfer_to(constant_u16(target), opcode_rts);
        builder_.SetInsertPoint(prediction_incorrect);
    }

    return new_pc;
}

void FunctionBuilder::control_transfer_to(llvm::Value *target, uint8_t opcode)
{
    assert(target->getType() == i16_type_);

    switch (opcode)
    {
        case opcode_rts:
        case opcode_rti:
        case opcode_bra:
        case opcode_bcc:
        case opcode_bcs:
        case opcode_bvc:
        case opcode_bvs:
        case opcode_beq:
        case opcode_bne:
        case opcode_bmi:
        case opcode_bpl:
        case opcode_implicit:
            // This control transfer never triggers a call callback.
            break;

        case opcode_jsr:
        {
            // This control transfer triggers a call callback if present. The
            // target address is known at compile time.
            llvm::ConstantInt *target_ci = 
                llvm::cast<llvm::ConstantInt>(target);
            uint16_t target16 = target_ci->getLimitedValue();
            if (callbacks_.call[target16] != 0)
            {
                return_jsr_complex(target);
                return;
            }

            // We also need to check if the two bytes pushed onto the stack by
            // the JSR have invalidated any JITted code and return control to
            // our caller if so.
            //
            // Note that we work with a tmp_s i8 local so that if the stack
            // pointer wrapped during the JSR pushes we will still work
            // correctly here.
            llvm::Value *tmp_s = 
                builder_.CreateAdd(register_load(s_), constant_u8(1));
            llvm::Value *stack_addr1 = 
                builder_.CreateAdd(constant_u16(stack), zext_i16(tmp_s));
            tmp_s = builder_.CreateAdd(tmp_s, constant_u8(1));
            llvm::Value *stack_addr2 = 
                builder_.CreateAdd(constant_u16(stack), zext_i16(tmp_s));

            llvm::BasicBlock *code_not_modified_block = 
                llvm::BasicBlock::Create(context_, "code_not_modified");
            llvm::BasicBlock *code_addr1_not_modified_block = 
                llvm::BasicBlock::Create(context_, "code_addr1_not_modified", 
                                         llvm_function_);
            llvm::BasicBlock *code_modified_block = 
                llvm::BasicBlock::Create(context_, "code_modified", 
                                         llvm_function_);

            const AddressRange stack_range(stack, stack + 0x100);
            llvm::Value *stack_addr1_is_code = 
                is_code_at(BoundedAddress(*this, stack_addr1, stack_range));
            builder_.CreateCondBr(stack_addr1_is_code, code_modified_block, 
                                  code_addr1_not_modified_block);

            builder_.SetInsertPoint(code_addr1_not_modified_block);
            llvm::Value *stack_addr2_is_code = 
                is_code_at(BoundedAddress(*this, stack_addr2, stack_range));
            builder_.CreateCondBr(stack_addr2_is_code, code_modified_block, 
                                  code_not_modified_block);

            builder_.SetInsertPoint(code_modified_block);
            return_jsr_complex(target);

            llvm_function_->getBasicBlockList().push_back(
                code_not_modified_block);
            builder_.SetInsertPoint(code_not_modified_block);
            break;
        }

        case opcode_jmp_abs:
        {
            // This control transfer triggers a call callback if present. The
            // target address is known at compile time.
            llvm::ConstantInt *target_ci = 
                llvm::cast<llvm::ConstantInt>(target);
            uint16_t target16 = target_ci->getLimitedValue();
            if (callbacks_.call[target16] != 0)
            {
                return_control_transfer_indirect(target, opcode);
                return;
            }
            break;
        }

        case opcode_jmp_ind_abs:
        case opcode_jmp_indx_abs:
        {
            // This control transfer triggers a call callback if present. The
            // target address is only known at run time.
            assert(!llvm::isa<llvm::ConstantInt>(target));
            llvm::Value *call_callback_addr = builder_.CreateGEP(
                call_callbacks_, 
                llvm::ArrayRef<llvm::Value *>(zext_i32(target)));
            llvm::Value *call_callback = 
                builder_.CreateLoad(call_callback_addr);
            llvm::BasicBlock *call_callback_block = 
                llvm::BasicBlock::Create(context_, "call_callback", 
                                         llvm_function_);
            llvm::BasicBlock *no_call_callback_block = 
                llvm::BasicBlock::Create(context_, "no_call_callback", 
                                         llvm_function_);
            llvm::Value *call_callback_not_null = 
                builder_.CreateIsNotNull(call_callback);
            builder_.CreateCondBr(call_callback_not_null, call_callback_block, 
                                  no_call_callback_block);

            builder_.SetInsertPoint(call_callback_block);
            return_control_transfer_indirect(target, opcode);

            builder_.SetInsertPoint(no_call_callback_block);
            break;
        }
    
        default:
            CANT_HAPPEN("Unexpected opcode 0x" << std::hex << opcode);
    }

    llvm::ConstantInt *target_ci = llvm::dyn_cast<llvm::ConstantInt>(target);
    if ((target_ci != 0) && (
            code_generated_for_address_[target_ci->getLimitedValue()] ||
            (pending_.find(target_ci->getLimitedValue()) != pending_.end())))
    {
        ensure_address_block_created(target_ci->getLimitedValue());
        // The target is within this function, so we can just branch there.
        builder_.CreateBr(address_block_[target_ci->getLimitedValue()]);
    }
    else
    {
        // The target isn't (knowably) within this function, so we have to
        // get there via our caller.
        return_control_transfer_direct(target);
    }
}

// All memory reads should be done via a call to this function, unless they are
// explicitly exempt from read callbacks.
llvm::Value *FunctionBuilder::memory_read(const BoundedAddress &ba)
{
    llvm::Value *addr = ba.addr();

    llvm::ConstantInt *addr_ci = llvm::dyn_cast<llvm::ConstantInt>(addr);
    if (addr_ci != 0)
    {
        uint16_t addr16 = addr_ci->getLimitedValue();
        TRACE("Load at compile-time constant address 0x" << std::hex << 
              std::setfill('0') << std::setw(4) << addr16);
        if (callbacks_.read[addr16] != 0)
        {
            TRACE("Read callback exists at constant address");
            llvm::Value *callback = 
                constant_ptr(callbacks_.read[addr16], "read_callback");
            return call_read_callback(callback, addr);
        }
    
        // Actually do the read from memory.
        return memory_read_untrapped(ba);
    }
    else
    {
        if (callback_in_bounds(callbacks_.read, ba.bounds()))
        {
            TRACE("Read callback may exist; runtime check required");
            llvm::Value *read_callback_addr = builder_.CreateGEP(
                read_callbacks_, llvm::ArrayRef<llvm::Value *>(zext_i32(addr)));
            llvm::Value *read_callback = 
                builder_.CreateLoad(read_callback_addr);
            llvm::BasicBlock *read_callback_block = 
                llvm::BasicBlock::Create(context_, "read_callback", 
                                         llvm_function_);
            llvm::BasicBlock *no_read_callback_block = 
                llvm::BasicBlock::Create(context_, "no_read_callback", 
                                         llvm_function_);
            llvm::BasicBlock *memory_read_done_block = 
                llvm::BasicBlock::Create(context_, "memory_read_done");
            llvm::Value *read_callback_not_null = 
                builder_.CreateIsNotNull(read_callback);
            builder_.CreateCondBr(read_callback_not_null, read_callback_block, 
                                  no_read_callback_block);

            builder_.SetInsertPoint(read_callback_block);
            llvm::Value *result = call_read_callback(read_callback, ba.addr());
            builder_.CreateStore(result, read_callback_result_);
            builder_.CreateBr(memory_read_done_block);

            builder_.SetInsertPoint(no_read_callback_block);
            builder_.CreateStore(memory_read_untrapped(ba), 
                                 read_callback_result_);
            builder_.CreateBr(memory_read_done_block);
            
            llvm_function_->getBasicBlockList().push_back(
                memory_read_done_block);
            builder_.SetInsertPoint(memory_read_done_block);
            return builder_.CreateLoad(read_callback_result_);
        }
        else
        {
            TRACE("No read callback within address bounds");
            // Actually do the read from memory.
            return memory_read_untrapped(ba);
        }
    }
}

llvm::Value *FunctionBuilder::memory_read_untrapped(const BoundedAddress &ba)
{
    llvm::Value *host_addr = builder_.CreateGEP(
        memory_base_, llvm::ArrayRef<llvm::Value *>(zext_i32(ba.addr())));
    return builder_.CreateLoad(host_addr);
}

// All memory writes should be done via a call to this function, unless they
// are explicitly exempt from triggering write callbacks.
//
// Note that because this may return to the caller to indicate
// result_write_to_code or result_write_callback, it must be the last
// code-generation function called when translating an opcode, as any
// subsequent code may not be executed.
void FunctionBuilder::memory_write(const BoundedAddress &ba,
                                 llvm::Value *data, uint16_t next_opcode_at)
{
    llvm::ConstantInt *addr_ci = llvm::dyn_cast<llvm::ConstantInt>(ba.addr());
    if (addr_ci != 0)
    {
        uint16_t addr16 = addr_ci->getLimitedValue();
        TRACE("Store at compile-time constant address 0x" << std::hex << 
              std::setfill('0') << std::setw(4) << addr16);
        if (callbacks_.write[addr16] != 0)
        {
            TRACE("Write callback exists at constant address");
            return_write_callback(next_opcode_at, ba.addr(), data);
            return;
        }
    }
    else
    {
        if (callback_in_bounds(callbacks_.write, ba.bounds()))
        {
            TRACE("Write callback may exist; runtime check required");
            llvm::Value *write_callback_addr = builder_.CreateGEP(
                write_callbacks_, 
                llvm::ArrayRef<llvm::Value *>(zext_i32(ba.addr())));
            llvm::Value *write_callback = 
                builder_.CreateLoad(write_callback_addr);
            llvm::BasicBlock *write_callback_block = 
                llvm::BasicBlock::Create(context_, "write_callback", 
                                         llvm_function_);
            llvm::BasicBlock *no_write_callback_block = 
                llvm::BasicBlock::Create(context_, "no_write_callback", 
                                         llvm_function_);
            llvm::Value *write_callback_not_null = 
                builder_.CreateIsNotNull(write_callback);
            builder_.CreateCondBr(write_callback_not_null, write_callback_block, 
                                  no_write_callback_block);

            builder_.SetInsertPoint(write_callback_block);
            return_write_callback(next_opcode_at, ba.addr(), data);

            builder_.SetInsertPoint(no_write_callback_block);
        }
        else
        {
            TRACE("No write callback within address bounds");
        }
    }

    memory_write_untrapped(ba, data, next_opcode_at);
}

// Note that (like lib6502 proper) we don't externalise our registers before
// invoking the (read/write) callback or internalise them afterwards, so
// the callback doesn't see correct information if it examines the CPU state.
llvm::Value *FunctionBuilder::call_callback(
    llvm::Value *callback, llvm::Value *addr, 
    llvm::Value *data)
{
    return builder_.CreateCall3(callback, mpu_llvm_, addr, data, 
                                "callback_result");
}

llvm::Value *FunctionBuilder::call_read_callback(
    llvm::Value *callback, llvm::Value *addr)
{
    llvm::Value *result_int = call_callback(callback, addr, constant_u8(0));
    return builder_.CreateTrunc(result_int, i8_type_);
}

// Write to memory with no checks for modification of already JITted code or
// write callbacks.
void FunctionBuilder::memory_write_raw(const BoundedAddress &ba,
                                     llvm::Value *data)
{
    llvm::Value *host_addr = builder_.CreateGEP(
        memory_base_, llvm::ArrayRef<llvm::Value *>(zext_i32(ba.addr())));
    builder_.CreateStore(data, host_addr);
}

llvm::Value *FunctionBuilder::is_code_at(const BoundedAddress &ba)
{
    const AddressRange &bounds = ba.bounds();
    bool use_optimistic_write = !bounds.all_memory();
    for (AddressRange::const_iterator it = bounds.begin(); 
         use_optimistic_write && (it != bounds.end()); ++it)
    {
        uint16_t i = *it;
        if (code_at_address_[i])
        {
            TRACE("BoundedAddress " << ba << 
                  " includes known code at 0x" << std::hex << 
                  std::setfill('0') << std::setw(4) << i << 
                  "; can't use optimistic write");
            use_optimistic_write = false;
        }
    }
    
    if (use_optimistic_write)
    {
        optimistic_writes_.insert(ba.bounds());
        return constant_i1(false);
    }
    else
    {
        llvm::Value *code_at_address_flag_addr = builder_.CreateGEP(
            code_at_address_llvm_, 
            llvm::ArrayRef<llvm::Value *>(zext_i32(ba.addr())));
        return jit_bool_is_true(builder_.CreateLoad(code_at_address_flag_addr));
    }
}

// Write to memory, checking for modification of already JITted code but
// not for write callbacks.
//
// Note that because this may return to the caller to indicate
// result_write_to_code, it must be the last code-generation function called
// when translating an opcode, as any subsequent code may not be executed.
void FunctionBuilder::memory_write_untrapped(
    const BoundedAddress &ba, llvm::Value *data, 
    uint16_t next_opcode_at)
{
    // Actually do the write.
    memory_write_raw(ba, data);

    // Check for writes which modify JITted code.
    llvm::Value *just_modified_code = is_code_at(ba);

    // The optimiser would eliminate the dead branches if just_modified_code
    // is a constant false value, but to make the IR easier to read and perhaps
    // help the optimiser out, let's not generate pointless code in this case.
    llvm::ConstantInt *just_modified_ci = 
        llvm::dyn_cast<llvm::ConstantInt>(just_modified_code);
    if ((just_modified_ci != 0) && !(just_modified_ci->getLimitedValue()))
    {
        return;
    }

    llvm::BasicBlock *code_modified_block = 
        llvm::BasicBlock::Create(context_, "code_modified", llvm_function_);
    llvm::BasicBlock *code_not_modified_block = 
        llvm::BasicBlock::Create(context_, "code_not_modified", llvm_function_);
    builder_.CreateCondBr(just_modified_code, code_modified_block, 
                          code_not_modified_block);

    builder_.SetInsertPoint(code_modified_block);
    return_write_to_code(next_opcode_at, ba.addr());

    builder_.SetInsertPoint(code_not_modified_block);
}

void FunctionBuilder::return_pc(Result result, llvm::Value *new_pc)
{
    builder_.CreateStore(constant_i(result), function_result_);
    builder_.CreateStore(new_pc, pc_);
    builder_.CreateBr(epilogue_);
}

void FunctionBuilder::return_pc_addr(Result result, llvm::Value *new_pc, 
                                     llvm::Value *addr)
{
    builder_.CreateStore(constant_i(result), function_result_);
    builder_.CreateStore(new_pc, pc_);
    builder_.CreateStore(addr, builder_.CreateStructGEP(registers_, 11));
    builder_.CreateBr(epilogue_);
}

void FunctionBuilder::return_pc_data(Result result, llvm::Value *new_pc, 
                                     llvm::Value *data)
{
    builder_.CreateStore(constant_i(result), function_result_);
    builder_.CreateStore(new_pc, pc_);
    builder_.CreateStore(data, builder_.CreateStructGEP(registers_, 12));
    builder_.CreateBr(epilogue_);
}

void FunctionBuilder::return_pc_addr_data(
    Result result, llvm::Value *new_pc, llvm::Value *addr, llvm::Value *data)
{
    builder_.CreateStore(constant_i(result), function_result_);
    builder_.CreateStore(new_pc, pc_);
    builder_.CreateStore(addr, builder_.CreateStructGEP(registers_, 11));
    builder_.CreateStore(data, builder_.CreateStructGEP(registers_, 12));
    builder_.CreateBr(epilogue_);
}

void FunctionBuilder::return_control_transfer_direct(llvm::Value *new_pc)
{
    return_pc(result_control_transfer_direct, new_pc);
}

void FunctionBuilder::return_control_transfer_indirect(
    llvm::Value *new_pc, uint8_t opcode)
{
    return_pc_data(result_control_transfer_indirect, new_pc, 
                   constant_u8(opcode));
}

void FunctionBuilder::return_brk(llvm::Value *new_pc)
{
    return_pc(result_brk, new_pc);
}

void FunctionBuilder::return_jsr_complex(llvm::Value *new_pc)
{
    return_pc(result_jsr_complex, new_pc);
}

void FunctionBuilder::return_illegal_instruction(
    uint16_t new_pc, uint16_t opcode_at, uint8_t opcode)
{
    return_pc_addr_data(result_illegal_instruction, constant_u16(new_pc), 
                        constant_u16(opcode_at), constant_u8(opcode));
}

void FunctionBuilder::return_write_to_code(uint16_t new_pc, llvm::Value *addr)
{
    return_pc_addr(result_write_to_code, constant_u16(new_pc), addr);
}

void FunctionBuilder::return_write_callback(
    uint16_t new_pc, llvm::Value *addr, llvm::Value *data)
{
    return_pc_addr_data(
        result_write_callback, constant_u16(new_pc), addr, data);
}

void FunctionBuilder::return_invalid_bounds()
{
    builder_.CreateStore(constant_i(result_invalid_bounds), function_result_);
    builder_.CreateBr(epilogue_);
}

void FunctionBuilder::disassemble1(uint16_t &addr, const std::string &s)
{
    disassemble_hex_dump(addr, 1);
    disassembly_ << s << "\n";
    ++addr;
}

void FunctionBuilder::disassemble2(
    uint16_t &addr, const std::string &prefix, uint8_t &operand, 
    const std::string &suffix)
{
    disassemble_hex_dump(addr, 2);
    operand = operand8(addr);
    disassembly_ << prefix << hex_prefix << std::setw(2) << 
                    static_cast<int>(operand) << suffix;

    // This is a bit of a special case, but it works so...
    std::string::size_type l = prefix.length();
    if ((l > 1) && (prefix[l - 1] == '#') && isprint(operand))
    {
        disassembly_ << " ('" << static_cast<char>(operand) << "')";
    }

    disassembly_ << "\n";

    addr += 2;
}

void FunctionBuilder::disassemble3(
    uint16_t &addr, const std::string &prefix, uint16_t &operand, 
    const std::string &suffix)
{
    disassemble_hex_dump(addr, 3);
    operand = operand16(addr);
    disassembly_ << prefix << hex_prefix << std::setw(4) << operand << suffix << 
                    "\n";
    addr += 3;
}

void FunctionBuilder::disassemble_branch(
    uint16_t &addr, const std::string &s, uint16_t &target)
{
    disassemble_hex_dump(addr, 2);
    uint8_t operand = operand8(addr);
    int offset = (operand < 0x80) ? operand : -(0x100 - operand);
    // The branch is relative to the PC *after* it's been moved past the
    // branch instruction.
    addr += 2;
    target = addr + offset;
    disassembly_ << s << hex_prefix << std::setw(4) << target << "\n";
}

void FunctionBuilder::disassemble_hex_dump(uint16_t addr, int bytes)
{ 
    assert(bytes <= 3);
    disassembly_ << std::hex << std::setw(4) << std::setfill('0') << addr << 
                    " ";
    for (int i = 0; i < 3; ++i)
    {
        if (i < bytes)
        {
            disassembly_ << std::setw(2) << 
                            static_cast<int>(ct_memory_[addr + i]) << " ";
        }
        else
        {
            disassembly_ << "   ";
        }
    }
}
