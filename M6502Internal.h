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

#ifndef M6502INTERNAL_H
#define M6502INTERNAL_H

#include "FunctionManager.h"
#include "lib6502.h"
#include "LLVMStuff.h"
#include "Registers.h"

struct _M6502_Internal                                                           
{                                                                                
    _M6502_Internal(M6502 *mpu)
    : function_manager_(mpu), mode_(M6502_ModeHybrid), 
      max_instructions_(default_max_instructions_)
    {
    }

    Registers registers_;                                                        
    LLVMStuff llvm_stuff_;                                                       
    FunctionManager function_manager_;                                           

    M6502_Mode mode_;
    static const int default_max_instructions_ = 500;
    int max_instructions_;
};                                                                               

#endif
