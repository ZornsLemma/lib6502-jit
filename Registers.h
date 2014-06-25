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

#ifndef REGISTERS_H 
#define REGISTERS_H

#include <boost/utility.hpp>
#include <stdint.h>

#include "JitBool.h"

typedef struct _M6502 M6502;

struct Registers : boost::noncopyable
{
    uint8_t a;
    uint8_t x;
    uint8_t y;
    uint8_t s;
    JitBool flag_n;
    JitBool flag_v;
    JitBool flag_d;
    JitBool flag_i;
    JitBool flag_z;
    JitBool flag_c;
    uint16_t pc;

    // Pseudo-registers used to communicate state for callbacks; see the
    // comment describing the Result enumeration in FunctionBuilder.h.
    uint16_t addr;
    uint8_t data;

    void to_M6502_Registers(M6502 *mpu) const;
    void from_M6502_Registers(const M6502 *mpu);
};

#endif
