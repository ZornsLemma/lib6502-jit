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

int main(int argc, char *argv[])
{
  M6502    *mpu = M6502_new(0, 0, 0);
  parse_args(argc, argv, mpu);

  unsigned  pc  = 0x1000;
  unsigned saved_pc;

  M6502_setCallback(mpu, call,  0xf000, done  );
  M6502_setCallback(mpu, call,  0xffee, oswrch);

  gen2(0xa2, 0xff      ); // LDX #&FF
  gen1(0x9a            ); // TXS
  gen2(0xa9, 'A'       ); // LDA #'A'

  // LDA #'B' is 0xa9, 0x42. So if we execute a BRK at 0x42a7, it will
  // push 0x42, 0xa9 and the flags onto the stack. Since the stack grows
  // downwards those bytes will be in the right order for execution. We'll
  // additionally push an LDX immediate opcode so we can "execute" the flags
  // value. We can nearly force the flags to be whatever we like using PLP,
  // although the BRK will set the B and X bits in the stacked value. We
  // demonstrate this by explicitly masking off those bits in the values we
  // force into the flags.
  enum {
    flagX= (1<<5),	/* unused   	 */
    flagB= (1<<4) 	/* irq from brk  */
  };
  uint8_t mask = ~(flagX | flagB);
  gen2(0xa0, '0' & mask); // LDY #('0' with B/X masked off)
  gen1(0x5a            ); // PHY
  gen1(0x28            ); // PLP
  gen3(0x4c, 0xa7, 0x42); // JMP &42A7
  pc = 0x42a7;
  gen2(0x00, 0x00      ); // BRK
  saved_pc = pc;
  pc = 0x0; // BRK vector
  gen2(0xa9, 0xa2      ); // LDA #<LDX # opcode>
  gen1(0x48            ); // PHA
  gen3(0x4c, 0xfc, 0x01); // JMP &01FC
  pc = 0x200;
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen1(0x8a            ); // TXA
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen1(0x68            ); // PLA
  gen1(0x40            ); // RTI
  pc = saved_pc;

  // Let's do the same thing again, but this time code has already been
  // executed from that address on the stack, so we're verifying the change
  // is picked up. We do LDA #'C' this time, so we execute the BRK from
  // 0x43a7.
  gen2(0xa0, '1' & mask); // LDY #('1' with B/X masked off)
  gen1(0x5a            ); // PHY
  gen1(0x28            ); // PLP
  gen3(0x4c, 0xa7, 0x43); // JMP &43A7
  pc = 0x43a7;
  gen2(0x00, 0x00      ); // BRK

  gen3(0x4c, 0x00, 0xf0); // JMP &F000 (quit)

  M6502_setVector(mpu, RST, 0x1000);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);	/* We never reach here, but what the hey. */

  return 0;
}
