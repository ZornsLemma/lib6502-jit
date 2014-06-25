/* parse-args.c -- utility function for C test programs */

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

/* Some of this code is copy-and-pasted from run6502.c, but there's not enough
 * of it for me to want to complicate things even slightly by trying to share
 * it, especially since this is test code and somewhat distinct. 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib6502.h"

static const char *program= 0;
static M6502_Mode mode= M6502_ModeHybrid;
static int max_insns= 0; /* default */

enum {
  flagX= (1<<5),	/* unused   	 */
  flagB= (1<<4) 	/* irq from brk  */
};

void fail(const char *fmt, ...)
{
  va_list ap;
  fflush(stdout);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  exit(1);
}

static void usage(int status)
{
  FILE *stream = stderr;
  fprintf(stream, "usage: %s [option ...]\n", program);
  fprintf(stream, "  -h        -- help (print this message)\n");
  fprintf(stream, "  -mc       -- use compiled emulation mode\n");
  fprintf(stream, "  -mh       -- use hybrid emulation mode (default)\n");
  fprintf(stream, "  -mi       -- use interpreted emulation mode\n");
  fprintf(stream, "  -mx count -- maximum instructions to JIT (-mc/-mh)\n");
  exit(status);
}

static int doMode(M6502_Mode m)
{
  mode= m;
  return 0;
}

static int doMaxInsns(int argc, char **argv, M6502 *mpu)
{
  if (argc < 2) usage(1);
  char *end;
  unsigned long l= strtol(argv[1], &end, 10);
  if (*end) fail("bad number: %s", argv[1]);
  max_insns= l;
  return 1;
}

void parse_args(int argc, char *argv[], M6502 *mpu)
{
    program= argv[0];
    while (++argv, --argc > 0)
    {
	int n= 0;
	if      (!strcmp(*argv, "-h"))  usage(0);
	else if (!strcmp(*argv, "-mc")) n= doMode(M6502_ModeCompiled);
	else if (!strcmp(*argv, "-mh")) n= doMode(M6502_ModeHybrid);
	else if (!strcmp(*argv, "-mi")) n= doMode(M6502_ModeInterpreted);
	else if (!strcmp(*argv, "-mx")) n= doMaxInsns(argc, argv, mpu);
	else				usage(1);
	argc -= n;
	argv += n;
    }

    M6502_setMode(mpu, mode, max_insns);
}

void M6502_dump_masked(M6502 *mpu, char buffer[64])
{
    uint8_t orig_p = mpu->registers->p;
    mpu->registers->p &= ~(flagB | flagX);
    M6502_dump(mpu, buffer);
    mpu->registers->p = orig_p;
}
