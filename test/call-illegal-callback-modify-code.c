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

static uint16_t call_modify1_addr;
static uint16_t call_modify2_addr;
static uint16_t ill_modify1_addr;
static uint16_t ill_modify2_addr;

int done(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nBRK instruction: address %04X opcode %02X\n%s\n", address, data, buffer);
  exit(0);
}

int call(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\ncall: address %04X opcode %02X\n%s\n", address, data, buffer);
  mpu->memory[call_modify1_addr] += 1;
  mpu->memory[call_modify2_addr] += 2;
  return 0;
}

int ill(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nill: address %04X opcode %02X memory %02X\n%s\n", address, data, mpu->memory[address], buffer);
  mpu->memory[ill_modify1_addr] += 1;
  mpu->memory[ill_modify2_addr] += 2;
  return 0;
}

int oswrch(M6502 *mpu, uint16_t address, uint8_t data)
{
  putchar(mpu->registers->a);
  mpu->memory[0xffee] = 0x60; // RTS
  return 0;
}

int main(int argc, char *argv[])
{
  M6502    *mpu = M6502_new(0, 0, 0);
  parse_args(argc, argv, mpu);

  unsigned  pc  = 0x1000;

  M6502_setCallback(mpu, call,                     0, done  );
  M6502_setCallback(mpu, call,                0x2000, call  );
  M6502_setCallback(mpu, illegal_instruction,   0x13, ill   );
  M6502_setCallback(mpu, call,                0xffee, oswrch);

# define gen1(X)	(mpu->memory[pc++]= (uint8_t)(X))
# define gen2(X,Y)	gen1(X); gen1(Y)
# define gen3(X,Y,Z)	gen1(X); gen2(Y,Z)

  gen3(0x20,0x00,0x30); // JSR &3000
  gen1(0x13          ); // ill &13
  gen3(0x20,0x00,0x30); // JSR &3000
  gen1(0x13          ); // ill &13
  gen3(0x20,0x00,0x30); // JSR &3000
  gen3(0x20,0x00,0x20); // JSR &2000
  gen3(0x20,0x00,0x30); // JSR &3000
  gen3(0x20,0x00,0x20); // JSR &2000
  gen3(0x20,0x00,0x30); // JSR &3000
  gen2(0x00,0x00     ); // BRK

  pc = 0x2000;
  gen1(0x60          ); // RTS

  pc = 0x3000;
  gen2(0xa9,'C'      ); // LDA #'C'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  call_modify1_addr = pc + 1;
  gen2(0xa9,'A'      ); // LDA #'A'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  call_modify2_addr = pc + 1;
  gen2(0xa9,'A'      ); // LDA #'A'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  ill_modify1_addr = pc + 1;
  gen2(0xa9,'A'      ); // LDA #'A'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  ill_modify2_addr = pc + 1;
  gen2(0xa9,'A'      ); // LDA #'A'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  gen2(0xa9,'\n'     ); // LDA #'\n'
  gen3(0x20,0xee,0xff); // JSR &FFEE
  gen1(0x60          ); // RTS

  M6502_setVector(mpu, RST, 0x1000);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);	/* We never reach here, but what the hey. */

  return 0;
}
