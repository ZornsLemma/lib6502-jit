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

// JitBool is a typedef representing the type used for boolean flags in the
// JITted code, i.e. the CPU flag values and the 'code modified at' flag for
// each memory address. In reality this is not likely to change, but this at
// least helps to identify code which needs to change to support a different
// representation. FunctionBuilder.cpp also contains a number of helper
// functions which depend on the underlying type of JitBool.

#ifndef JITBOOL_H
#define JITBOOL_H

typedef uint8_t JitBool;
const JitBool jit_bool_false = 0;
const JitBool jit_bool_true = 1;

#endif
