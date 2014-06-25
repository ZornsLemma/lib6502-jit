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

#include "Function.h"

#include <errno.h>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include "valgrind.h"

#include "const.h"
#include "LLVMStuff.h"
#include "M6502Internal.h"
#include "Registers.h"
#include "util.h"

// Note that we call update_memory_snapshot() after invoking callbacks here, but
// not before. It would be correct to do so, but it's not necessary. Firstly, we
// arrange that the memory snapshot is kept up-to-date during execution under
// our control (i.e. not involving callbacks), so it isn't necessary. Secondly,
// even if it were necessary, it would be redundant, since any actions needed
// as a result of the update can wait until after the callback is called and the
// call after the callback would perform them.

namespace
{
    // We have the callback_pc argument to allow us to special-case the
    // contents of the PC register for lib6502 compatibility. Without this
    // we would always pass registers.pc, which is "address of the next
    // instruction to execute if the callback doesn't intervene" in PC;
    // this agrees with lib6502 for JMP (absolute and indirect) but not for JSR
    // or BRK.
    uint16_t handle_call_callback(M6502 *mpu, uint16_t callback_pc, 
                                  uint8_t opcode)
    {
        Registers &registers = mpu->internal->registers_;
        uint16_t default_next_pc = registers.pc;
        if (mpu->callbacks->call[registers.pc] != 0)
        {
            registers.pc = callback_pc;
            registers.to_M6502_Registers(mpu);
            TRACE("Call callback, mpu " << mpu << ", address 0x" << std::hex << 
                  std::setfill('0') << std::setw(4) << default_next_pc << 
                  ", data 0x" << std::setw(2) << static_cast<int>(opcode));
            uint16_t address = default_next_pc;
            if (opcode == opcode_brk)
            {
                address = callback_pc - 2; // lib6502 does this
            }
            int callback_result = 
                mpu->callbacks->call[default_next_pc](mpu, address, opcode);
            TRACE("Callback returned 0x" << std::hex << std::setfill('0') <<
                  std::setw(4) << callback_result);
            registers.from_M6502_Registers(mpu);
            mpu->internal->function_manager_.update_memory_snapshot();
            if (callback_result != 0)
            {
                return callback_result;
            }
        }
        return default_next_pc;
    }

    uint16_t get_stacked_pc(M6502 *mpu, int offset)
    {
        uint8_t s = mpu->internal->registers_.s;

        for (; offset > 0; --offset)
        {
            ++s;
        }

        ++s;
        uint8_t pushed_pc_low = mpu->memory[0x100 + s];
        ++s;
        uint8_t pushed_pc_high = mpu->memory[0x100 + s];
        return pushed_pc_low | (pushed_pc_high << 8);
    }

    uint16_t handle_push_and_control_transfer_opcode(
        M6502 *mpu, uint16_t callback_pc, uint8_t opcode, int bytes_pushed)
    {
        assert(bytes_pushed >= 2);

        uint8_t s = mpu->internal->registers_.s;
        for (int i = 0; i < bytes_pushed; ++i)
        {
            ++s;
            mpu->internal->function_manager_.code_modified_at(0x100 + s);
        }

        return handle_call_callback(mpu, callback_pc, opcode);
    }
}

Function::Function(
    M6502 *mpu, uint16_t address, const AddressSet &code_range, 
    const AddressSet &optimistic_writes, llvm::Function *llvm_function)
: mpu_(mpu),
  llvm_stuff_(mpu->internal->llvm_stuff_),
  address_(address),
  code_range_(code_range),
  optimistic_writes_(optimistic_writes),
  llvm_function_(llvm_function),
  jitted_function_(reinterpret_cast<Function::JitFunction>(
    llvm_stuff_.execution_engine_->getPointerToFunction(llvm_function)))
{
    llvm_stuff_.execution_engine_->runJITOnFunction(llvm_function_, &mci_);
}

Function::~Function()
{
    TRACE("Destructor for Function at address " << std::hex << 
          std::setfill('0') << std::setw(4) << address_);
    
    VALGRIND_DISCARD_TRANSLATIONS(mci_.address(), mci_.size());
    llvm_function_->eraseFromParent();
}

void Function::handle_complex_result(FunctionBuilder::Result result) const
{
    Registers &registers = mpu_->internal->registers_;

    switch (result)
    {
        case FunctionBuilder::result_control_transfer_direct:
            CANT_HAPPEN("Direct case reached handle_complex_result()");

        case FunctionBuilder::result_control_transfer_indirect:
            registers.pc = handle_call_callback(mpu_, registers.pc, 
                                                registers.data);
            break;

        case FunctionBuilder::result_brk:
            registers.pc = handle_push_and_control_transfer_opcode(
                mpu_, get_stacked_pc(mpu_, 1), opcode_brk, 3);
            break;

        case FunctionBuilder::result_jsr_complex:
            registers.pc = handle_push_and_control_transfer_opcode(
                mpu_, get_stacked_pc(mpu_, 0) + 1, opcode_jsr, 2);
            break;

        case FunctionBuilder::result_illegal_instruction:
        {
            registers.to_M6502_Registers(mpu_);
            TRACE("Illegal instruction callback, mpu " << mpu_ << 
                  ", address 0x" << std::hex << std::setfill('0') << 
                  std::setw(4) << registers.addr << ", data 0x" << 
                  std::setw(2) << static_cast<int>(registers.data));
            uint16_t new_pc = 
                mpu_->callbacks->illegal_instruction[registers.data](
                    mpu_, registers.addr, registers.data);
            TRACE("Callback returned 0x" << std::hex << std::setfill('0') <<
                  std::setw(4) << new_pc);
            registers.from_M6502_Registers(mpu_);
            mpu_->internal->function_manager_.update_memory_snapshot();
            if (new_pc != 0)
            {
                registers.pc = new_pc;
            }
            break;
        }

        case FunctionBuilder::result_write_to_code:
            TRACE("Code modified at 0x" << std::hex << std::setfill('0') << 
                  std::setw(4) << registers.addr);
            mpu_->internal->function_manager_.code_modified_at(registers.addr);
            break;

        case FunctionBuilder::result_write_callback:
        {
            TRACE("Write callback at 0x" << std::hex << std::setfill('0') <<
                  std::setw(4) << registers.addr << " with data 0x" << 
                  std::setw(4) << static_cast<int>(registers.data));
            // We *don't* invoke Registers.{to,from}_M6502Registers() before
            // and after the callback. We could do this, but lib6502 itself
            // (and therefore the lib6502 code used for interpreting in
            // lib6502-jit) doesn't do that, so this could be confusing
            // for client code. (For example, a callback might be written
            // to rely on this, it would work if called from compiled code
            // but wouldn't work if called from interpreted mode. So its
            // behaviour in hybrid mode would be random.)
            (void) mpu_->callbacks->write[registers.addr](
                mpu_, registers.addr, registers.data);
            mpu_->internal->function_manager_.update_memory_snapshot();
            break;
        }

        case FunctionBuilder::result_invalid_bounds:
            CANT_HAPPEN("Invalid bounds inside Function for address 0x" <<
                        std::hex << std::setfill('0') << std::setw(4) <<
                        address_);

        default:
            CANT_HAPPEN("Unknown result " << result << " from JIT function");
    }
}

#ifdef LOG

namespace
{
    std::string indent(int n, const std::string &s)
    {
        std::string prefix = spaces(n);
        return apply_prefix(prefix, s);
    }
}

std::string Function::dump_all() const
{
    std::stringstream s;
    s << "Function at 0x" << std::hex << std::setfill('0') << std::setw(4) <<
         address_ << ":\n";
    s << spaces(1) << "Code range:\n" << code_range_.dump(2) << "\n";
    s << spaces(1) << "Optimistic writes at:\n" << optimistic_writes_.dump(2) <<
         "\n";
    s << spaces(1) << "6502 machine code:\n" << indent(2, disassembly_) << "\n";
    s << spaces(1) << "Unoptimised IR:\n" << indent(2, unoptimised_ir_) << "\n";
    s << spaces(1) << "Optimised IR:\n" << indent(2, optimised_ir_) << "\n";;
    s << spaces(1) << "Host machine code:\n" << indent(2, dump_machine_code());
    return s.str();
}

#endif

namespace
{
    template <class Handle, class CloseFnType, CloseFnType close_fn>
    class AutoClose : boost::noncopyable
    {
    public:
        AutoClose(Handle h)
        : open_(true), h_(h)
        {
        }

        int close()
        {
            open_ = false;
            return close_fn(h_);
        }

        ~AutoClose()
        {
            if (open_)
            {
                close_fn(h_); // ignore return code, nothing we can do if it fails
            }
        }

    private:
        bool open_;
        Handle h_;
    };

    typedef int (*FdClose)(int);
    typedef AutoClose<int, FdClose, ::close> FdAutoClose;
    typedef int (*PopenClose)(FILE *);
    typedef AutoClose<FILE *, PopenClose, ::pclose> PopenAutoClose;
}

#ifdef LOG

std::string Function::dump_machine_code() const
{
    try
    {
        // What a performance! The basic idea of outputting .bytes directives,
        // assembling those and then disassembling the result is taken from
        // libjit's dump_object_code(); the implementation is not copied.

        char as_output_file[] = "/tmp/lib6502-jit-XXXXXX";

        errno = 0;

        // mkstemp() creates a unique filename and opens it. We unlink the file
        // immediately so it has no name; this minimises (but does not
        // eliminate; we might be killed between mkstemp() and unlink()) the
        // chance of the file being left lying around. Since we need a name for
        // the 'as' and 'objdump' commands, we use /dev/fd/nn to refer to it
        // afterwards.
        int fd = mkstemp(as_output_file);
        if (fd == -1)
        {
            fail_errno_or("mkstemp() failed");
        }
        FdAutoClose auto_close_fd(fd);
        if (unlink(as_output_file) == -1)
        {
            fail_errno_or("unlink() failed");
        }

        {
            std::stringstream as_command;
            as_command << "as -o /dev/fd/" << fd << " 2>/dev/null";
            FILE *f = popen(as_command.str().c_str(), "w");
            if (f == 0)
            {
                fail_errno_or("popen() failed (for 'as')");
            }
            PopenAutoClose auto_close_f(f);
            unsigned char *p = static_cast<unsigned char *>(mci_.address());              
            unsigned char *end = p + mci_.size();                                         
            for (; p < end; ++p)                                                         
            {                                                                            
                if (fprintf(f, ".byte %d\n", *p) < 0)
                {
                    fail("Error writing to 'as' pipe");
                }
            }                                                                            
            if (auto_close_f.close() != 0)
            {
                fail_errno_or("Error closing 'as' pipe");
            }
        }

        if (lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1))
        {
            fail_errno_or("Error seeking on temporary file");
        }

        std::stringstream objdump_command;
        // As far as I can tell, there's no guarantee how mci_.address() [a
        // pointer type] will be represented in the stringstream, but in
        // practice this code is not very portable anyway and this is the least
        // of our worries...
        objdump_command << "objdump --adjust-vma=" << 
                           mci_.address() << " -d /dev/fd/" << fd << " 2>&1";
        FILE *g = popen(objdump_command.str().c_str(), "r");
        if (g == 0)
        {
            fail_errno_or("popen() failed (for 'objdump')");
        }
        PopenAutoClose auto_close_g(g);

        std::stringstream code;
        char buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), g)) > 0)
        {
            code << std::string(buffer, bytes_read);
        }
        if (ferror(g))
        {
            fail("Error reading from 'objdump' pipe");
        }
        if (auto_close_g.close() != 0)
        {
            fail_errno_or("Error closing 'objdump' pipe");
        }
        if (auto_close_fd.close() != 0)
        {
            fail_errno_or("Error closing temporary file");
        }

        return code.str();
    }
    catch (std::exception &e)
    {
        // Dumping out the generated machine code is decidedly not critical, so
        // we don't allow the exception to propagate.
        return std::string("Unable to dump machine code: ") + e.what();
    }
}

void Function::fail(const std::string &error) const
{
    throw std::runtime_error(error);
}

void Function::fail_errno_or(const std::string &error) const
{
    if (errno == 0)
    {
        fail(error);
    }
    else
    {
        // strerror_r() exists in various versions. If you have problems getting
        // this to compile, it's probably OK to just use:
        //     const char *error = strerror(errno);
        // given a) the limited amount of threading here and b) the fact this is
        // only used to report rare errors in debug-only logging code. If push
        // really comes to shove you can just do:
        //     const char *error = 0;
        // and you'll just get unhelpful error messages.
        char buffer[1024];
        const char *error = strerror_r(errno, buffer, sizeof(buffer));
        if (error != 0)
        {
            fail(error);
        }
        else
        {
            fail("Error occurred, and strerror() probably failed as well");
        }
    }
}

#endif
