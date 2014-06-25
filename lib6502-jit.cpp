/* lib6502-jit.cpp -- MOS Technology 6502 emulator	-*- C -*- */

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

#include "const.h"
#include "Function.h"
#include "FunctionBuilder.h"
#include "FunctionManager.h"
#include "M6502Internal.h"
#include "Registers.h"
#include "util.h"

static void outOfMemory(void)
{
    die("out of memory");
}

M6502 *M6502_new(M6502_Registers *registers, M6502_Memory memory, M6502_Callbacks *callbacks)
{
  M6502 *mpu= (M6502 *) calloc(1, sizeof(M6502));
  if (!mpu) outOfMemory();

  if (!registers)  { registers = (M6502_Registers *)calloc(1, sizeof(M6502_Registers));  mpu->flags |= M6502_RegistersAllocated; }
  if (!memory   )  { memory    = (uint8_t         *)calloc(1, sizeof(M6502_Memory   ));  mpu->flags |= M6502_MemoryAllocated;    }
  if (!callbacks)  { callbacks = (M6502_Callbacks *)calloc(1, sizeof(M6502_Callbacks));  mpu->flags |= M6502_CallbacksAllocated; }

  if (!registers || !memory || !callbacks) outOfMemory();

  mpu->registers = registers;
  mpu->memory    = memory;
  mpu->callbacks = callbacks;

  try
  {
    mpu->internal = new _M6502_Internal(mpu);
  }
  catch (std::exception &e)
  {
    die(e.what());
  }

  return mpu;
}
 
void M6502_delete(M6502 *mpu)
{
  if (mpu->flags & M6502_CallbacksAllocated) free(mpu->callbacks);
  if (mpu->flags & M6502_MemoryAllocated   ) free(mpu->memory);
  if (mpu->flags & M6502_RegistersAllocated) free(mpu->registers);
  delete mpu->internal;

  free(mpu);
}

void M6502_setMode(M6502 *mpu, M6502_Mode mode, int arg)
{
    mpu->internal->mode_ = mode;

    if (arg == 0)
    {
        arg = M6502_Internal::default_max_instructions_;
    }
    mpu->internal->max_instructions_ = arg;
} 

extern "C" void M6502_run_interpreted(M6502 *mpu, int instructions_left);

// I don't know if it's "supposed" to work, but it doesn't seem completely
// unreasonable for a lib6502 client to do a setjmp() before invoking
// M6502_run() and have a callback function longjmp() out of the emulation. I
// believe this will work with lib6502 itself, and I would like this emulation
// to do the same.  (Note that currently for both lib6502 and lib6502-jit,
// read/write callbacks don't see an up-to-date M6502_Registers object and so
// the setjmp/longjmp trick would result in restarting execution in the wrong
// place with the wrong registers. Call callbacks and illegal instruction
// callbacks should work though.)
//
// To this end, M6502_run_compiled() and M6502_run_hybrid() both update the
// Registers object from the M6502_Registers object on entry to pick up the
// current state. They also both ensure they call update_memory_snapshot() as
// appropriate in case the caller modified memory before invoking M6502_run()
// again.

static void M6502_run_compiled(M6502 *mpu)
{
    FunctionManager &function_manager = mpu->internal->function_manager_;
    function_manager.update_memory_snapshot();

    Registers &registers = mpu->internal->registers_;
    registers.from_M6502_Registers(mpu);

    while (true)
    {
        Function *f = function_manager.get_function(registers.pc);
        TRACE("Executing Function object for address 0x" << std::hex <<
              std::setfill('0') << std::setw(4) << registers.pc);
        f->execute();
    }
}

#ifdef LOG

static std::string M6502_dump_str(M6502 *mpu)
{
    char buffer[64];
    M6502_dump(mpu, buffer);
    return buffer;
}

#endif

static void M6502_run_hybrid(M6502 *mpu)
{
    FunctionManager &function_manager = mpu->internal->function_manager_;
    Registers &registers = mpu->internal->registers_;
    registers.from_M6502_Registers(mpu);
    TRACE("About to interpret, CPU state: " << M6502_dump_str(mpu));
    while (true)
    {
        const int instructions_to_interpret = 100;
        M6502_run_interpreted(mpu, instructions_to_interpret);
        if (function_manager.jit_thread_idle())
        {
            TRACE("JIT thread is idle");
            registers.from_M6502_Registers(mpu);
            function_manager.update_memory_snapshot();
            Function *f;
            while ((f = function_manager.get_function_lazy(registers.pc)) != 0)
            {
                TRACE("Executing Function object for address 0x" << std::hex <<
                      std::setfill('0') << std::setw(4) << registers.pc);
                f->execute();
            }
            TRACE("No Function object available for address 0x" << std::hex <<
                  std::setfill('0') << std::setw(4) << registers.pc <<
                  ", falling back to interpreter");
            registers.to_M6502_Registers(mpu);
            TRACE("About to interpret, CPU state: " << M6502_dump_str(mpu));
        }
    }
}

void M6502_run(M6502 *mpu)
{
    try
    {
        switch (mpu->internal->mode_)
        {
            case M6502_ModeInterpreted:
                while (true)
                {
                    M6502_run_interpreted(mpu, std::numeric_limits<int>::max());
                }
                break;

            case M6502_ModeCompiled:
                M6502_run_compiled(mpu);
                break;

            case M6502_ModeHybrid:
                M6502_run_hybrid(mpu);
                break;

            default:
                die("Unknown execution mode in M6502_run()");
        }

        die("M6502_run() returned!");
    }
    catch (std::exception &e)
    {
        die(e.what());
    }
}
