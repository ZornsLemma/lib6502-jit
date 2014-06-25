/* lib6502.h -- MOS Technology 6502 emulator	-*- C -*- */

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

#ifndef __m6502_h
#define __m6502_h

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
  extern "C"
{
#endif

typedef struct _M6502		M6502;
typedef struct _M6502_Registers	M6502_Registers;
typedef struct _M6502_Callbacks	M6502_Callbacks;
typedef struct _M6502_Internal  M6502_Internal;

typedef int   (*M6502_Callback)(M6502 *mpu, uint16_t address, uint8_t data);

typedef M6502_Callback	M6502_CallbackTable[0x10000];
typedef M6502_Callback	M6502_IllegalInstructionCallbackTable[0x100];
typedef uint8_t		M6502_Memory[0x10000];

enum {
  M6502_NMIVector= 0xfffa,  M6502_NMIVectorLSB= 0xfffa,  M6502_NMIVectorMSB= 0xfffb,
  M6502_RSTVector= 0xfffc,  M6502_RSTVectorLSB= 0xfffc,  M6502_RSTVectorMSB= 0xfffd,
  M6502_IRQVector= 0xfffe,  M6502_IRQVectorLSB= 0xfffe,  M6502_IRQVectorMSB= 0xffff
};

struct _M6502_Registers
{
  uint8_t   a;	/* accumulator */
  uint8_t   x;	/* X index register */
  uint8_t   y;	/* Y index register */
  uint8_t   p;	/* processor status register */
  uint8_t   s;	/* stack pointer */
  uint16_t pc;	/* program counter */
};

struct _M6502_Callbacks
{
  M6502_CallbackTable read;
  M6502_CallbackTable write;
  M6502_CallbackTable call;
  M6502_IllegalInstructionCallbackTable illegal_instruction;
};

struct _M6502_Internal;

struct _M6502
{
  M6502_Registers *registers;
  uint8_t	  *memory;
  M6502_Callbacks *callbacks;
  unsigned int	   flags;

  /* The following is implementation-specific; client code should only use the
   * above members.
   */
  M6502_Internal  *internal;
};

enum {
  M6502_RegistersAllocated = 1 << 0,
  M6502_MemoryAllocated    = 1 << 1,
  M6502_CallbacksAllocated = 1 << 2
};

typedef enum {
  M6502_ModeInterpreted,
  M6502_ModeCompiled,
  M6502_ModeHybrid
} M6502_Mode;

extern M6502 *M6502_new(M6502_Registers *registers, M6502_Memory memory, M6502_Callbacks *callbacks);
extern void   M6502_reset(M6502 *mpu);
extern void   M6502_nmi(M6502 *mpu);
extern void   M6502_irq(M6502 *mpu);
extern void   M6502_run(M6502 *mpu);
extern int    M6502_disassemble(M6502 *mpu, uint16_t addr, char buffer[64]);
extern void   M6502_dump(M6502 *mpu, char buffer[64]);
extern void   M6502_delete(M6502 *mpu);
extern void   M6502_setMode(M6502 *mpu, M6502_Mode mode, int arg);

#define M6502_getVector(MPU, VEC)			\
  ( ( ((MPU)->memory[M6502_##VEC##VectorLSB]) )		\
    | ((MPU)->memory[M6502_##VEC##VectorMSB] << 8) )

#define M6502_setVector(MPU, VEC, ADDR)						\
  ( ( ((MPU)->memory[M6502_##VEC##VectorLSB]= ((uint8_t)(ADDR)) & 0xff) )	\
    , ((MPU)->memory[M6502_##VEC##VectorMSB]= (uint8_t)((ADDR) >> 8)) )

#define M6502_getCallback(MPU, TYPE, ADDR)	((MPU)->callbacks->TYPE[ADDR])
#define M6502_setCallback(MPU, TYPE, ADDR, FN)	((MPU)->callbacks->TYPE[ADDR]= (FN))


#ifdef __cplusplus
}
#endif

#endif /* __m6502_h */
