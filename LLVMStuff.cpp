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

#include "LLVMStuff.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/TargetSelect.h"

LLVMStuff::LLVMStuff()
: module_(new llvm::Module("lib6502-jit", llvm::getGlobalContext())),
  builder_(llvm::getGlobalContext())
{
    llvm::InitializeNativeTarget();

    std::string error;
    execution_engine_ = 
        llvm::EngineBuilder(module_.get()).setErrorStr(&error).create();
    if (execution_engine_ == 0)
    {
        throw std::runtime_error("Could not create LLVM ExecutionEngine: " + 
                                 error);
    }
}

LLVMStuff::~LLVMStuff()
{
}
