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

#include "Registers.h"

#include "const.h"
#include "lib6502.h"
#include "M6502Internal.h"

void Registers::to_M6502_Registers(M6502 *mpu) const
{
    M6502_Registers &er = *(mpu->registers);
    Registers &ir = mpu->internal->registers_;

    er.a = ir.a;
    er.x = ir.x;
    er.y = ir.y;
    er.s = ir.s;
    er.p = 0;
    if (ir.flag_n) er.p |= flagN;
    if (ir.flag_v) er.p |= flagV;
    if (ir.flag_d) er.p |= flagD;
    if (ir.flag_i) er.p |= flagI;
    if (ir.flag_z) er.p |= flagZ;
    if (ir.flag_c) er.p |= flagC;
    er.pc = ir.pc;
}

void Registers::from_M6502_Registers(const M6502 *mpu)
{
    M6502_Registers &er = *(mpu->registers);
    Registers &ir = mpu->internal->registers_;

    ir.a = er.a;
    ir.x = er.x;
    ir.y = er.y;
    ir.s = er.s;
    ir.flag_n = ((er.p & flagN) != 0);
    ir.flag_v = ((er.p & flagV) != 0);
    ir.flag_d = ((er.p & flagD) != 0);
    ir.flag_i = ((er.p & flagI) != 0);
    ir.flag_z = ((er.p & flagZ) != 0);
    ir.flag_c = ((er.p & flagC) != 0);
    ir.pc = er.pc;
}
