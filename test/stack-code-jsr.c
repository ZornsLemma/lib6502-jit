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

int main(int argc, char *argv[])
{
  M6502    *mpu = M6502_new(0, 0, 0);
  parse_args(argc, argv, mpu);

  unsigned  pc  = 0x1000;
  unsigned saved_pc;

  M6502_setCallback(mpu, call,       0, done  );
  M6502_setCallback(mpu, call,  0xffee, oswrch);

  gen2(0xa2, 0xff      ); // LDX #&FF
  gen1(0x9a            ); // TXS
  gen2(0xa9, 'A'       ); // LDA #'A'

  // LDA #'B' is 0xa9, 0x42. So if we execute a JSR at 0x42a7, it will
  // push 0x42 and then 0xa9 onto the stack. Since the stack grows downwards
  // those bytes will be in the right order for execution.
  gen3(0x4c, 0xa7, 0x42); // JMP &42A7
  pc = 0x42a7;
  gen3(0x20, 0x00, 0x30); // JSR &3000
  saved_pc = pc;
  pc = 0x3000;
  gen3(0x4c, 0xfe, 0x01); // JMP &01FE
  pc = 0x200;
  gen3(0x20, 0xee, 0xff); // JSR &FFEE
  gen1(0x60            ); // RTS
  pc = saved_pc;

  // Let's do the same thing again, but this time code has already been
  // executed from that address on the stack, so we're verifying the change
  // is picked up. We do LDA #'C' this time, so we execute the JSR from
  // 0x43a7.
  gen3(0x4c, 0xa7, 0x43); // JMP &43A7
  pc = 0x43a7;
  gen3(0x20, 0x00, 0x30); // JSR &3000

  gen2(0x00, 0x00      ); // BRK

  M6502_setVector(mpu, RST, 0x1000);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);	/* We never reach here, but what the hey. */

  return 0;
}
