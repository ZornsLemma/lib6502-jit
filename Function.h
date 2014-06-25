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

#ifndef FUNCTION_H
#define FUNCTION_H

#include <boost/shared_ptr.hpp>
#include <boost/utility.hpp>
#include "llvm/CodeGen/MachineCodeInfo.h"
#include "llvm/IR/Value.h"

#include "AddressSet.h"
#include "FunctionBuilder.h"
#include "lib6502.h"

struct LLVMStuff;

class Function : boost::noncopyable
{
public:
    Function(M6502 *mpu, uint16_t address, const AddressSet &code_range, 
             const AddressSet &optimistic_writes, 
             llvm::Function *llvm_function);
    ~Function();

    uint16_t address() const
    {
        return address_;
    }

    const AddressSet &code_range() const
    {
        return code_range_;
    }

    const AddressSet &optimistic_writes() const
    {
        return optimistic_writes_;
    }

    void execute() const
    {
        FunctionBuilder::Result result = 
            static_cast<FunctionBuilder::Result>((*jitted_function_)());
        if (result != FunctionBuilder::result_control_transfer_direct)
        {
            handle_complex_result(result);
        }
    }

    #ifdef LOG
        void set_disassembly(const std::string &s)
        {
            disassembly_ = s;
        }

        void set_unoptimised_ir(const std::string &s)
        {
            unoptimised_ir_ = s;
        }

        void set_optimised_ir(const std::string &s)
        {
            optimised_ir_ = s;
        }

        std::string dump_all() const;

        std::string dump_machine_code() const;
    #endif

private:
    void handle_complex_result(FunctionBuilder::Result result) const;

    #ifdef LOG
        void fail(const std::string &error) const;
        void fail_errno_or(const std::string &error) const;
    #endif

    M6502 *mpu_;
    LLVMStuff &llvm_stuff_;
    uint16_t address_;
    AddressSet code_range_;
    AddressSet optimistic_writes_;
    llvm::Function *llvm_function_;
    llvm::MachineCodeInfo mci_;

    typedef int (*JitFunction)();
    JitFunction jitted_function_;
    
    #ifdef LOG
        std::string disassembly_;
        std::string unoptimised_ir_;
        std::string optimised_ir_;
    #endif
};

#endif
