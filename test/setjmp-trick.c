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

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib6502.h"
#include "test-utils.h"

static jmp_buf env;

int done(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nBRK instruction: address %04X opcode %02X\n%s\n", address, data, buffer);
  longjmp(env, 1);
  exit(0);
}

int call(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\ncall: address %04X opcode %02X\n%s\n", address, data, buffer);
  mpu->registers->pc = address;
  longjmp(env, 2);
  return 0;
}

int ill(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nill: address %04X opcode %02X memory %02X\n%s\n", address, data, mpu->memory[address], buffer);
  longjmp(env, 3);
  return 0;
}

int main(int argc, char *argv[])
{
  M6502    *mpu = M6502_new(0, 0, 0);
  parse_args(argc, argv, mpu);

  unsigned  pc  = 0x1000;

  /* Read and write callbacks don't provide the correct, up-to-date CPU state
   * in the M6502 object, so this trick is a non-starter with them.
   */

  M6502_setCallback(mpu, call,                     0, done);
  M6502_setCallback(mpu, call,                0x2000, call);
  M6502_setCallback(mpu, call,                0x3000, call);
  M6502_setCallback(mpu, call,                0x4000, call);
  M6502_setCallback(mpu, illegal_instruction,   0x13, ill );
  M6502_setCallback(mpu, illegal_instruction,   0x44, ill );
  M6502_setCallback(mpu, illegal_instruction,   0x5c, ill );

# define gen1(X)	(mpu->memory[pc++]= (uint8_t)(X))
# define gen2(X,Y)	gen1(X); gen1(Y)
# define gen3(X,Y,Z)	gen1(X); gen2(Y,Z)

  gen1(0x13          );
  gen1(0x44          );
  gen1(0x13          ); // not executed, 0x44 is a two-byte illegal instruction
  gen1(0x5C          );
  gen1(0x13          ); // not executed, 0x5C is a two-byte illegal instruction
  gen1(0x13          ); // not executed, 0x5C is a two-byte illegal instruction
  gen3(0x20,0x00,0x20); // JSR &2000
  gen3(0xad,0x00,0x50); // LDA &5000
  gen2(0x00,0x00     ); // BRK

  pc = 0x2000;
  gen3(0x8d,0x00,0x50); // STA &5000
  gen3(0x4c,0x00,0x30); // JMP &3000

  pc = 0x3000;
  gen2(0xa9,0x00     ); // LDA #0
  gen3(0x8d,0x76,0x32); // STA &3276
  gen2(0xa9,0x40     ); // LDA #&40
  gen3(0x8d,0x77,0x32); // STA &3277
  gen3(0x6c,0x76,0x32); // JMP (&3276)

  pc = 0x4000;
  gen1(0x60          ); // RTS

  M6502_setVector(mpu, RST, 0x1000);

  M6502_reset(mpu);
  while (1)
  {
    volatile int result = setjmp(env);
    if (result == 0)
    {
    	M6502_run(mpu);
    }
    else
    {
      printf("\nsetjmp() returned %d\n", result);
      if (result == 1)
      {
	break;
      }
    }
  }
  M6502_delete(mpu);

  return 0;
}
