/* Copyright (c) 2005 Ian Piumarta
 * Copyright (c) 2014 Steven Flintham
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

#ifndef CONST_H
#define CONST_H

#include <stdint.h>

namespace
{
    const uint8_t opcode_brk = 0x00;
    const uint8_t opcode_rti = 0x40;
    const uint8_t opcode_rts = 0x60;
    const uint8_t opcode_bra = 0x80;
    const uint8_t opcode_bcc = 0x90;
    const uint8_t opcode_bcs = 0xb0;
    const uint8_t opcode_bvc = 0x50;
    const uint8_t opcode_bvs = 0x70;
    const uint8_t opcode_beq = 0xf0;
    const uint8_t opcode_bne = 0xd0;
    const uint8_t opcode_bpl = 0x10;
    const uint8_t opcode_bmi = 0x30;
    const uint8_t opcode_jsr = 0x20;
    const uint8_t opcode_jmp_abs = 0x4c;
    const uint8_t opcode_jmp_ind_abs = 0x6c;
    const uint8_t opcode_jmp_indx_abs = 0x7c;

    enum {
      flagN= (1<<7),	/* negative 	 */
      flagV= (1<<6),	/* overflow 	 */
      flagX= (1<<5),	/* unused   	 */
      flagB= (1<<4),	/* irq from brk  */
      flagD= (1<<3),	/* decimal mode  */
      flagI= (1<<2),	/* irq disable   */
      flagZ= (1<<1),	/* zero          */
      flagC= (1<<0)	/* carry         */
    };
    
    const uint32_t memory_size = 0x10000;
    const uint16_t stack = 0x100;
}

#endif
