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

#ifndef FUNCTIONBUILDER_H
#define FUNCTIONBUILDER_H

#include <boost/shared_ptr.hpp>
#include <boost/utility.hpp>
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/IR/Value.h"
#include <map>
#include <set>
#include <sstream>

#include "AddressSet.h"
#include "const.h"
#include "JitBool.h"
#include "lib6502.h"

class Function;
struct LLVMStuff;

class FunctionBuilder : boost::noncopyable
{
public:
    // Create a FunctionBuilder object which can be used to build a Function
    // representing the code starting at 'address'. The Function object built
    // will operate on the given M6502 object. The 'code_at_address' array
    // will be used at compile time and at runtime to decide if writes to
    // memory may invalidate already JITted code. The memory inside the M6502
    // object will be used when the Funtion object executes, but ct_memory
    // will be used at compile time to determine the instructions to compile;
    // see FunctionManager for more on this.
    FunctionBuilder(M6502 *mpu, const uint8_t *ct_memory, 
                    JitBool *code_at_address, uint16_t address);

    boost::shared_ptr<Function> build();

    // Status codes returned by the JITted function
    enum Result
    {
        // Control has transferred to the address in registers.pc. No call
        // callback should be invoked, either because the JITted function knows
        // there is no applicable call callback or because the control transfer
        // is via an instruction which does not trigger call callbacks.
        result_control_transfer_direct,

        // Control has transferred to the address in registers.pc via an
        // instruction which is eligible for call callbacks. registers.data
        // contains the opcode of the instruction which transferred
        // control. The caller should check for an applicable call
        // callback. registers.addr is *not* updated; the addr value for
        // the callback is registers.pc.
        result_control_transfer_indirect,

        // A BRK instruction has just been executed and registers.pc updated
        // to point to the BRK vector. The caller should check to see if the
        // stack pushes implicitly performed by BRK have invalidated any
        // already-JITted code and for a call callback on the BRK vector.
        // Neither registers.addr nor registers.data are updated.
        result_brk,

        // A JSR instruction has just been executed and registers.pc
        // updated to point to the destination address. One or both of the
        // following may be true: - the stack pushes implicitly performed
        // have invalidated some
        //   already-JITted code
        // - a call callback is registered on the destination address It is not
        // guaranteed that either of these is the case, although in practice
        // with this implementation at least one should be true. Not all JSR
        // instructions will necessarily cause the JITted function to return
        // this value, hence the result code is result_jsr_*complex* not just
        // result_jsr. Neither registers.addr nor registers.data are updated.
        result_jsr_complex,

        // An illegal instruction has been executed and registers.pc updated to
        // point to the following opcode. registers.addr contains the address
        // of the illegal instruction and registers.data its opcode. The
        // caller should check to see if a callback is registered.
        result_illegal_instruction,

        // A memory write has been executed which changed an address marked
        // as holding code. registers.addr contains the address modified. The
        // caller should invalidate any JITted functions for this address.
        result_write_to_code,

        // A memory write has occurred which triggers a write callback. Memory
        // has not been updated. registers.addr and registers.data contain the
        // address and the data being written respectively. The caller should
        // invoke the write callback and check for writes to already-JITted
        // code.
        result_write_callback,

        // Internal bounds generated for an instruction's address range were
        // found to be invalid by self-checking code. This can only occur
        // in debug builds and then only if there is a bug in FunctionBuilder.
        result_invalid_bounds
    };

private:
    uint16_t build_at(uint16_t ct_pc);

    uint8_t operand8(uint16_t opcode_at);
    uint16_t operand16(uint16_t opcode_at);

    llvm::Value *constant_i1(bool c);
    llvm::Value *constant_u8(uint8_t c);
    llvm::Value *constant_u16(uint16_t c);
    llvm::Value *constant_u32(uint32_t c);
    llvm::Value *constant_u64(uint64_t c);

    template <class T>
    llvm::Value *constant_ptr(T *p, const std::string &name)
    {
        llvm::Value *v = constant_u64(reinterpret_cast<unsigned long>(p));
        // The name passed in never seems to be used, but maybe this will
        // change in the future. It doesn't really do us any harm to pass
        // it in anyway.
        return builder_.CreateIntToPtr(
            v, llvm::TypeBuilder<T *, false>::get(llvm::getGlobalContext()), 
            name);
    }

    llvm::Value *constant_i(int c);

    llvm::Value *constant_jb(JitBool c);
    llvm::Value *convert_i1_to_jb(llvm::Value *v);
    llvm::Value *convert_i8_to_jb(llvm::Value *v);
    llvm::Value *convert_i16_to_jb(llvm::Value *v);
    llvm::Value *jit_bool_is_true(llvm::Value *v);
    llvm::Value *jit_bool_is_false(llvm::Value *v);

    llvm::Value *convert_i1_to_i8(llvm::Value *v);

    llvm::Value *zext_i16(llvm::Value *v);
    llvm::Value *zext_i32(llvm::Value *v);
    llvm::Value *sext_i16(llvm::Value *v);
    llvm::Value *trunc_i8(llvm::Value *v);
    llvm::Value *create_u16(llvm::Value *low_byte, llvm::Value *high_byte);

    struct Register
    {
        llvm::Value *v_;
        bool modified_;
    };
    void initialise_i8_reg(Register &r, int structure_index, 
                           const std::string &name);
    void initialise_jb_reg(Register &r, int structure_index, 
                           const std::string &name);

    void ensure_address_block_created(uint16_t addr);

    void return_pc(Result result, llvm::Value *new_pc);
    void return_pc_addr(Result result, llvm::Value *new_pc, llvm::Value *addr);
    void return_pc_data(Result result, llvm::Value *new_pc, llvm::Value *data);
    void return_pc_addr_data(Result result, llvm::Value *new_pc, 
                             llvm::Value *addr, llvm::Value *data);
    void return_control_transfer_direct(llvm::Value *new_pc);
    void return_control_transfer_indirect(llvm::Value *new_pc, uint8_t opcode);
    void return_brk(llvm::Value *new_pc);
    void return_jsr_complex(llvm::Value *new_pc);
    void return_illegal_instruction(uint16_t new_pc, uint16_t opcode_at, 
                                    uint8_t opcode);
    void return_write_to_code(uint16_t new_pc, llvm::Value *addr);
    void return_write_callback(uint16_t new_pc, llvm::Value *addr, 
                               llvm::Value *data);
    void return_invalid_bounds();

    class BoundedAddress;

    llvm::Value *register_load(const Register &r);
    void register_store(llvm::Value *v, Register &r);

    typedef llvm::Value *(FunctionBuilder::*OpFn)(llvm::Value *data);
    void register_op(OpFn op, Register &r);
    void memory_op(OpFn op, const BoundedAddress &ba, uint16_t next_opcode_at);

    llvm::Value *is_code_at(const BoundedAddress &addr);

    void adc(llvm::Value *data);
    void adc_llvm(llvm::Value *data);
    void adc_binary(llvm::Value *data);
    void adc_decimal(llvm::Value *data);
    void adc_binary_llvm(llvm::Value *data);
    void adc_decimal_llvm(llvm::Value *data);
    void And(llvm::Value *data);
    llvm::Value *asl(llvm::Value *data);
    void bit(llvm::Value *data);
    void branch(Register &flag, bool branch_if, uint16_t target);
    void cmp(llvm::Value *r, llvm::Value *data);
    void cmp_llvm(llvm::Value *r, llvm::Value *data);
    llvm::Value *dec(llvm::Value *data);
    void eor(llvm::Value *data);
    llvm::Value *inc(llvm::Value *data);
    void ld(Register &r, llvm::Value *data);
    llvm::Value *lsr(llvm::Value *data);
    void ora(llvm::Value *data);
    void pop_flags();
    llvm::Value *pop_u8();
    llvm::Value *pop_u16();
    void push_u8_raw(llvm::Value *data);
    void push_u16_raw(uint16_t u);
    void push_u8(llvm::Value *data, uint16_t next_opcode_at);
    llvm::Value *rol(llvm::Value *data);
    llvm::Value *ror(llvm::Value *data);
    void sbc(llvm::Value *data);
    void sbc_binary(llvm::Value *data);
    void sbc_decimal(llvm::Value *data);
    void sbc_overflow(llvm::Value *data, 
                      llvm::Value *borrow);
    void transfer(const Register &from, Register &to);
    llvm::Value *trb(llvm::Value *data);
    llvm::Value *tsb(llvm::Value *data);

    void set_nz(llvm::Value *data);
    void set_z(llvm::Value *data);

    llvm::Value *flag_byte();
    void flag_byte_bit(const Register &flag_reg, uint8_t flag_bit);

    void illegal_instruction(uint16_t &ct_pc, int bytes);

    BoundedAddress zp(uint8_t addr);
    BoundedAddress abs(uint16_t addr);
    BoundedAddress abs_index(llvm::Value *abs, 
                           llvm::Value *index);
    BoundedAddress zp_index(llvm::Value *zp, 
                             llvm::Value *r);
    BoundedAddress zp_post_index(
        llvm::Value *zp, llvm::Value *index);
    BoundedAddress zp_pre_index(
        llvm::Value *zp, llvm::Value *index);

    llvm::Value *check_predicted_rts(uint16_t subroutine_addr);

    // A special opcode used as the third argument to control_transfer_to
    // when there is no explicit opcode causing the control transfer; this
    // is just a documented way to signal that the control transfer is direct
    // and cannot trigger a call callback.
    enum {
        opcode_implicit = 0xff
    };
    void control_transfer_to(llvm::Value *target, uint8_t opcode);

    llvm::Value *memory_read(const BoundedAddress &ba);
    llvm::Value *memory_read_untrapped(const BoundedAddress &ba);

    void memory_write(const BoundedAddress &ba,
                           llvm::Value *data, uint16_t next_opcode_at);
    void memory_write_untrapped(const BoundedAddress &ba,
                                llvm::Value *data, uint16_t next_opcode_at);
    void memory_write_raw(const BoundedAddress &ba,
                               llvm::Value *data);

    llvm::Value *call_callback(
        llvm::Value *callback, llvm::Value *addr, 
        llvm::Value *data);
    llvm::Value *call_read_callback(
        llvm::Value *callback, llvm::Value *addr);

    void disassemble1(uint16_t &addr, const std::string &s);
    void disassemble2(uint16_t &addr, const std::string &prefix, 
                      uint8_t &operand, const std::string &suffix = "");
    void disassemble3(uint16_t &addr, const std::string &prefix, 
                      uint16_t &operand, const std::string &suffix = "");
    void disassemble_branch(uint16_t &addr, const std::string &s, 
                            uint16_t &target);
    void disassemble_hex_dump(uint16_t addr, int bytes);

    bool built_;

    M6502 *const mpu_;
    JitBool *code_at_address_;
    const uint16_t address_;
    const uint8_t *const ct_memory_;
    // callbacks_ is strictly redundant as it's available inside mpu, but
    // it's convenient.
    const M6502_Callbacks &callbacks_;

    AddressSet code_range_;
    AddressSet optimistic_writes_;

    std::stringstream disassembly_;

    int instructions_;
    const int max_instructions_;

    // This could be an AddressSet but since we "rely" on the order of
    // iteration for pending_ it seems better to be explicit; we don't need
    // any of the range-handling convenience of AddressSet here anyway.
    std::set<uint16_t> pending_;

    std::map<uint16_t, AddressSet> predicted_rts_targets_;

    llvm::LLVMContext &context_;

    llvm::Type *const native_int_type_;
    llvm::PointerType *const callback_type_;
    llvm::Type *const i1_type_;
    llvm::Type *const i8_type_;
    llvm::Type *const i16_type_;
    llvm::Type *const i32_type_;
    llvm::Type *const i64_type_;
    llvm::Type *const jit_bool_type_;

    llvm::IRBuilder<> &builder_;

    llvm::Function *llvm_function_;

    llvm::Value *registers_;
    llvm::Value *code_at_address_llvm_;
    llvm::Value *read_callbacks_;
    llvm::Value *write_callbacks_;
    llvm::Value *call_callbacks_;
    llvm::Value *memory_base_;
    llvm::Value *mpu_llvm_;

    llvm::Value *function_result_;

    // Note that address_block_ and code_generated_for_address_ aren't
    // redundant; address_block_ elements are created (for example) when
    // a branch means the corresponding address must have a BasicBlock
    // created for use as a branch target, but that doesn't mean code has
    // been generated for it yet.
    llvm::BasicBlock *address_block_[memory_size];
    bool code_generated_for_address_[memory_size];

    Register a_;
    Register x_;
    Register y_;
    Register s_;
    Register flag_n_;
    Register flag_v_;
    Register flag_d_;
    Register flag_i_;
    Register flag_z_;
    Register flag_c_;
    llvm::Value *pc_;

    llvm::Value *read_callback_result_;
    llvm::Value *p_tmp_;
    llvm::Value *l_tmp_;
    llvm::Value *s_tmp_;
    llvm::Value *t_tmp_;

    llvm::BasicBlock *epilogue_;
};

#endif
