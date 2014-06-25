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

#ifndef LLVMSTUFF_H
#define LLVMSTUFF_H

#include <boost/shared_ptr.hpp>
#include <boost/utility.hpp>
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include <stdexcept>

struct LLVMStuff : boost::noncopyable
{
    LLVMStuff();
    ~LLVMStuff();

    llvm::ExecutionEngine *execution_engine_;
    boost::shared_ptr<llvm::Module> module_;
    llvm::IRBuilder<> builder_;

};

#endif
