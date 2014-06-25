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

int brk(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nBRK: address %04X opcode %02X\n%s\n", address, data, buffer);
  exit(0);
}

int ill(M6502 *mpu, uint16_t address, uint8_t data)
{
  char buffer[64];
  M6502_dump_masked(mpu, buffer);
  printf("\nill: address %04X opcode %02X memory %02X\n%s\n", address, data, mpu->memory[address], buffer);
  if (data == 0x03)
  {
    M6502_nmi(mpu);
  }
  else if (data == 0x13)
  {
    M6502_irq(mpu);
  } 

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

  /* 0x3000 is the IRQ/BRK vector, but call callbacks don't trigger on
   * interrupts, so this is only called on BRK.
   */
  M6502_setCallback(mpu, call,                0x3000, brk   );

  M6502_setCallback(mpu, illegal_instruction,   0x03, ill   );
  M6502_setCallback(mpu, illegal_instruction,   0x13, ill   );
  M6502_setCallback(mpu, call,                0xffee, oswrch);

# define gen1(X)	(mpu->memory[pc++]= (uint8_t)(X))
# define gen2(X,Y)	gen1(X); gen1(Y)
# define gen3(X,Y,Z)	gen1(X); gen2(Y,Z)

  gen1(0x58          ); // CLI
  gen2(0xa9,'A'      ); // LDA #'A'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x03          ); // NMI
  gen2(0xa9,'B'      ); // LDA #'B'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x13          ); // IRQ
  gen2(0xa9,'C'      ); // LDA #'C'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x78          ); // SEI
  gen1(0x13          ); // IRQ (ignored)
  gen1(0x03          ); // NMI
  gen1(0x13          ); // IRQ (ignored)
  gen2(0xa9,'D'      ); // LDA #'D'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x58          ); // CLI
  gen1(0x13          ); // IRQ
  gen2(0x00,0x00     ); // BRK

  pc = 0x2000;
  gen2(0xa9,'N'      ); // LDA #'N'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x40          ); // RTI

  pc = 0x3000;
  gen2(0xa9,'I'      ); // LDA #'I'
  gen3(0x20,0xee,0xff); // JSR &ffee
  gen1(0x40          ); // RTI

  M6502_setVector(mpu, RST, 0x1000);
  M6502_setVector(mpu, NMI, 0x2000);
  M6502_setVector(mpu, IRQ, 0x3000);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);	/* We never reach here, but what the hey. */

  return 0;
}
