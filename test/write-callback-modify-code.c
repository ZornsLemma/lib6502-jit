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

#include <stdio.h>
#include <stdlib.h>

#include "lib6502.h"
#include "test-utils.h"

int done(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nBRK instruction: address %04X opcode %02X\n%s\n", address, data, buffer);
  exit(0);
}

int oswrch(M6502 *mpu, uint16_t address, uint8_t data)
{
  putchar(mpu->registers->a);
  mpu->memory[0xffee] = 0x60; // RTS
  return 0;
}

# define gen1(X)	(mpu->memory[pc++]= (uint8_t)(X))
# define gen2(X,Y)	gen1(X); gen1(Y)
# define gen3(X,Y,Z)	gen1(X); gen2(Y,Z)

int wr(M6502 *mpu, uint16_t address, uint8_t data)
{
    if (address != 0x42)
    {
    	abort();
    }

    unsigned pc = 0x6000;
    gen2(0xa9, data);       // LDA #data
    gen3(0x4c, 0x00, 0x20); // JMP &2000
    return 0;
}

int main(int argc, char *argv[])
{
  M6502    *mpu = M6502_new(0, 0, 0);
  parse_args(argc, argv, mpu);

  unsigned  pc  = 0x1000;

  M6502_setCallback(mpu, call,      0, done);
  M6502_setCallback(mpu, call, 0xffee, oswrch);
  M6502_setCallback(mpu, write,  0x42, wr  );

  gen2(0xa9, '>'       ); // LDA #'>'
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen2(0xa2, 'A'       ); // LDX #'A'
  gen3(0x8e, 0x42, 0x00); // STX &0042
  gen3(0x20, 0x00, 0x60); // JSR &6000
  gen1(0xe8            ); // INX
  gen2(0xe0, 'Z'+1     ); // CPX #('Z'+1)
  gen2(0x90, 0xf5      ); // BCC to STX

  gen2(0xa0, 0x05      ); // LDY #&05
  gen2(0xa9, '>'       ); // LDA #'>'
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen2(0xa2, 'A'       ); // LDX #'A'
  gen2(0x96, 0x42-0x05 ); // STX (&42-&05),Y
  gen3(0x20, 0x00, 0x60); // JSR &6000
  gen1(0xe8            ); // INX
  gen2(0xe0, 'Z'+1     ); // CPX #('Z'+1)
  gen2(0x90, 0xf6      ); // BCC to STX

  gen2(0x00, 0x00      ); // BRK

  pc = 0x2000;
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen1(0x60            ); // RTS

  M6502_setVector(mpu, RST, 0x1000);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);	/* We never reach here, but what the hey. */

  return 0;
}
