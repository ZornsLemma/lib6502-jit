/* run6502.c -- 6502 emulator shell			-*- C -*- */

/* Copyright (c) 2005 Ian Piumarta
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

/* Last edited: 2005-11-02 01:18:58 by piumarta on margaux.local
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>

#include "config.h"
#include "lib6502.h"

#undef VERSION
#define VERSION	PACKAGE_NAME " " PACKAGE_VERSION " " PACKAGE_COPYRIGHT

typedef uint8_t  byte;
typedef uint16_t word;

static char *program= 0;

static M6502_Mode mode= M6502_ModeHybrid;
static int max_insns= 0; /* default */

static byte bank[0x10][0x4000];

static uint64_t system_time_base;


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


void pfail(const char *msg)
{
  fflush(stdout);
  perror(msg);
  exit(1);
}


#define rts							\
  {								\
    word pc;							\
    pc  = mpu->memory[++mpu->registers->s + 0x100];		\
    pc |= mpu->memory[++mpu->registers->s + 0x100] << 8;	\
    return pc + 1;						\
  }


uint64_t pseudo_system_time(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) == -1)
  {
    pfail("clock_gettime() failed");
  }
  long hsec= t.tv_nsec / 10000000;
  return (((uint64_t) t.tv_sec) * 100) + hsec;
}

int osword(M6502 *mpu, word address, byte data)
{
  byte *params= mpu->memory + mpu->registers->x + (mpu->registers->y << 8);

  switch (mpu->registers->a)
    {
    case 0x00: /* input line */
      /* On entry: XY+0,1=>string area,
       *	   XY+2=maximum line length,
       *	   XY+3=minimum acceptable ASCII value,
       *	   XY+4=maximum acceptable ASCII value.
       * On exit:  Y is the line length (excluding CR),
       *	   C is set if Escape terminated input.
       */
      {
	word  offset= params[0] + (params[1] << 8);
	byte *buffer= mpu->memory + offset;
	byte  length= params[2], minVal= params[3], maxVal= params[4], b= 0;
	if (!fgets((char *) buffer, length, stdin))
	  {
	    putchar('\n');
	    exit(0);
	  }
	for (b= 0;  b < length;  ++b)
	  if ((buffer[b] < minVal) || (buffer[b] > maxVal) || ('\n' == buffer[b]))
	    break;
	buffer[b]= 13;
	mpu->registers->y= b;
	mpu->registers->p &= 0xFE;
	break;
      }

    case 0x01: /* read system time */
      /* On exit: XY+0..4=>5 byte time in hundredths of a second
       */
      {
	uint64_t system_time= pseudo_system_time() - system_time_base;
	int i;
	for (i= 0;  i < 5;  ++i)
	{
	  params[i]= system_time & 0xFF;
	  system_time>>= 8;
	}
	break;
      }

    case 0x05: /* read I/O processor memory */
      /* On entry: XY+0..3=>address to read from
       * On exit:  XY+4   =>the byte read
       */
    {
	word addr= params[0] + (params[1] << 8);
	params[4]= mpu->memory[addr];
	break;
    }

    default:
      {
	char state[64];
	M6502_dump(mpu, state);
	fflush(stdout);
	fprintf(stderr, "\nOSWORD %s\n", state);
	fail("ABORT");
      }
      break;
    }
  
  rts;
}


int osbyte(M6502 *mpu, word address, byte data)
{
  switch (mpu->registers->a)
    {
    case 0x7A:	/* perform keyboard scan */
      mpu->registers->x= 0x00;
      break;

    case 0x7E:	/* acknowledge detection of escape condition */
      return 1;
      break;

    case 0x82:	/* read machine higher order address */
      mpu->registers->y= 0x00;
      mpu->registers->x= 0x00;
      break;

    case 0x83:	/* read top of OS ram address (OSHWM) */
      mpu->registers->y= 0x0E;
      mpu->registers->x= 0x00;
      break;

    case 0x84:	/* read bottom of display ram address */
      mpu->registers->y= 0x80;
      mpu->registers->x= 0x00;
      break;

    case 0x89:	/* motor control */
      break;

    case 0xDA:	/* read/write number of items in vdu queue (stored at 0x026A) */
      return 0;
      break;

    default:
      {
	char state[64];
	M6502_dump(mpu, state);
	fflush(stdout);
	fprintf(stderr, "\nOSBYTE %s\n", state);
	fail("ABORT");
      }
      break;
    }

  rts;
}


int oscli(M6502 *mpu, word address, byte data)
{
  byte *params= mpu->memory + mpu->registers->x + (mpu->registers->y << 8);
  char  command[1024], *ptr= command;
  int   ret;
  while (('*' == *params) || (' ' == *params))
    ++params;
  while (13 != *params)
    *ptr++= *params++;
  *ptr= '\0';
  ret= system(command);
  if ((ret == -1) || (WIFEXITED(ret) && (WEXITSTATUS(ret) == 127)))
    {
      fflush(stdout);
      fprintf(stderr, "\nsystem() failed\n");
    }
  rts;
}


int oswrch(M6502 *mpu, word address, byte data)
{
  switch (mpu->registers->a)
    {
    case 0x0C:
      fputs("\033[2J\033[H", stdout);
      break;

    default:
      putchar(mpu->registers->a);
      break;
    }
  fflush(stdout);
  rts;
}


static int writeROM(M6502 *mpu, word address, byte value)
{
  return 0;
}


static int bankSelect(M6502 *mpu, word address, byte value)
{
  memcpy(mpu->memory + 0x8000, bank[value & 0x0F], 0x4000);
  return 0;
}


static int doBtraps(int argc, char **argv, M6502 *mpu)
{
  unsigned addr;

  /* Acorn Model B ROM and memory-mapped IO */

  for (addr= 0x8000;  addr <= 0xFBFF;  ++addr)  mpu->callbacks->write[addr]= writeROM;
  for (addr= 0xFC00;  addr <= 0xFEFF;  ++addr)  mpu->memory[addr]= 0xFF;
  for (addr= 0xFE30;  addr <= 0xFE33;  ++addr)  mpu->callbacks->write[addr]= bankSelect;
  for (addr= 0xFE40;  addr <= 0xFE4F;  ++addr)  mpu->memory[addr]= 0x00;
  for (addr= 0xFF00;  addr <= 0xFFFF;  ++addr)  mpu->callbacks->write[addr]= writeROM;

  /* anything already loaded at 0x8000 appears in bank 0 */

  memcpy(bank[0x00], mpu->memory + 0x8000, 0x4000);

  /* fake a few interesting OS calls */

# define trap(vec, addr, func)   mpu->callbacks->call[addr]= (func)
  trap(0x020C, 0xFFF1, osword);
  trap(0x020A, 0xFFF4, osbyte);
//trap(0x0208, 0xFFF7, oscli );	/* enable this to send '*COMMAND's to system(3) :-) */
  trap(0x020E, 0xFFEE, oswrch);
  trap(0x020E, 0xE0A4, oswrch);	/* NVWRCH */
#undef trap

  system_time_base= pseudo_system_time();

  return 0;
}


static void usage(int status)
{
  FILE *stream= status ? stderr : stdout;
  fprintf(stream, VERSION"\n");
  fprintf(stream, "please send bug reports to: %s\n", PACKAGE_BUGREPORT);
  fprintf(stream, "\n");
  fprintf(stream, "usage: %s [option ...]\n", program);
  fprintf(stream, "       %s [option ...] -B [image ...]\n", program);
  fprintf(stream, "  -B                -- minimal Acorn 'BBC Model B' compatibility\n");
  fprintf(stream, "  -d addr last      -- dump memory between addr and last\n");
  fprintf(stream, "  -G addr           -- emulate getchar(3) at addr\n");
  fprintf(stream, "  -h                -- help (print this message)\n");
  fprintf(stream, "  -I addr           -- set IRQ vector\n");
  fprintf(stream, "  -l addr file      -- load file at addr\n");
  fprintf(stream, "  -M addr           -- emulate memory-mapped stdio at addr\n");
  fprintf(stream, "  -mc               -- use compiled emulation mode\n");
  fprintf(stream, "  -mh               -- use hybrid emulation mode (default)\n");
  fprintf(stream, "  -mi               -- use interpreted emulation mode\n");
  fprintf(stream, "  -mx count         -- maximum instructions to JIT (-mc/-mh)\n");
  fprintf(stream, "  -N addr           -- set NMI vector\n");
  fprintf(stream, "  -P addr           -- emulate putchar(3) at addr\n");
  fprintf(stream, "  -R addr           -- set RST vector\n");
  fprintf(stream, "  -s addr last file -- save memory from addr to last in file\n");
  fprintf(stream, "  -v                -- print version number then exit\n");
  fprintf(stream, "  -X addr           -- terminate emulation if PC reaches addr\n");
  fprintf(stream, "  -x                -- exit without further ado\n");
  fprintf(stream, "  image             -- '-l 8000 image' in available ROM slot\n");
  fprintf(stream, "\n");
  fprintf(stream, "'last' can be an address (non-inclusive) or '+size' (in bytes)\n");
  exit(status);
}


static int doHelp(int argc, char **argv, M6502 *mpu)
{
  usage(0);
  return 0;
}


static int doVersion(int argc, char **argv, M6502 *mpu)
{
  puts(VERSION);
  exit(0);
  return 0;
}


static unsigned long htol(char *hex)
{
  char *end;
  unsigned long l= strtol(hex, &end, 16);
  if (*end) fail("bad hex number: %s", hex);
  return l;
}


static int loadInterpreter(M6502 *mpu, word start, const char *path)
{
  FILE   *file= 0;
  int     count= 0;
  byte   *memory= mpu->memory + start;
  size_t  max= 0x10000 - start;
  int     c= 0;

  if ((!(file= fopen(path, "r"))) || ('#' != fgetc(file)) || ('!' != fgetc(file)))
    return 0;
  while ((c= fgetc(file)) >= ' ')
    ;
  while ((count= fread(memory, 1, max, file)) > 0)
    {
      memory += count;
      max -= count;
    }
  fclose(file);
  return 1;
}


static int save(M6502 *mpu, word address, unsigned length, const char *path)
{
  FILE *file= 0;
  int   count= 0;
  if (!(file= fopen(path, "w")))
    return 0;
  while ((count= fwrite(mpu->memory + address, 1, length, file)))
    {
      address += count;
      length -= count;
    }
  fclose(file);
  return 1;
}


static int load(M6502 *mpu, word address, const char *path)
{
  FILE  *file= 0;
  int    count= 0;
  size_t max= 0x10000 - address;
  if (!(file= fopen(path, "r")))
    return 0;
  while ((count= fread(mpu->memory + address, 1, max, file)) > 0)
    {
      address += count;
      max -= count;
    }
  fclose(file);
  return 1;
}


static int doLoadInterpreter(int argc, char **argv, M6502 *mpu)
{
  if (argc < 3) usage(1);
  if (!loadInterpreter(mpu, htol(argv[1]), argv[2])) pfail(argv[2]);
  return 2;
}


static int doLoad(int argc, char **argv, M6502 *mpu)	/* -l addr file */
{
  if (argc < 3) usage(1);
  if (!load(mpu, htol(argv[1]), argv[2])) pfail(argv[2]);
  return 2;
}


static int doSave(int argc, char **argv, M6502 *mpu)	/* -l addr size file */
{
  if (argc < 4) usage(1);
  if (!save(mpu, htol(argv[1]), htol(argv[2]), argv[3])) pfail(argv[3]);
  return 3;
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


#define doVEC(VEC)					\
  static int do##VEC(int argc, char **argv, M6502 *mpu)	\
    {							\
      unsigned addr= 0;					\
      if (argc < 2) usage(1);				\
      addr= htol(argv[1]);				\
      M6502_setVector(mpu, VEC, addr);			\
      return 1;						\
    }

doVEC(IRQ);
doVEC(NMI);
doVEC(RST);

#undef doVEC


static int gTrap(M6502 *mpu, word addr, byte data)	{ mpu->registers->a= getchar();  rts; }
static int pTrap(M6502 *mpu, word addr, byte data)	{ putchar(mpu->registers->a);  rts; }

static int doGtrap(int argc, char **argv, M6502 *mpu)
{
  unsigned addr;
  if (argc < 2) usage(1);
  addr= htol(argv[1]);
  M6502_setCallback(mpu, call, addr, gTrap);
  return 1;
}

static int doPtrap(int argc, char **argv, M6502 *mpu)
{
  unsigned addr;
  if (argc < 2) usage(1);
  addr= htol(argv[1]);
  M6502_setCallback(mpu, call, addr, pTrap);
  return 1;
}


static int mTrapRead(M6502 *mpu, word addr, byte data)	{ return getchar(); }
static int mTrapWrite(M6502 *mpu, word addr, byte data)	{ return putchar(data); }

static int doMtrap(int argc, char **argv, M6502 *mpu)
{
  unsigned addr= 0;
  if (argc < 2) usage(1);
  addr= htol(argv[1]);
  M6502_setCallback(mpu, read,  addr, mTrapRead);
  M6502_setCallback(mpu, write, addr, mTrapWrite);
  return 1;
}


static int xTrap(M6502 *mpu, word addr, byte data)	{ exit(0);  return 0; }

static int doXtrap(int argc, char **argv, M6502 *mpu)
{
  unsigned addr= 0;
  if (argc < 2) usage(1);
  addr= htol(argv[1]);
  M6502_setCallback(mpu, call, addr, xTrap);
  return 1;
}


static int doDisassemble(int argc, char **argv, M6502 *mpu)
{
  unsigned addr= 0, last= 0;
  if (argc < 3) usage(1);
  addr= htol(argv[1]);
  last= ('+' == *argv[2]) ? addr + htol(1 + argv[2]) : htol(argv[2]);
  while (addr < last)
    {
      char insn[64];
      int  i= 0, size= M6502_disassemble(mpu, addr, insn);
      printf("%04X ", addr);
      while (i++ < size)  printf("%02X", mpu->memory[addr + i - 1]);
      while (i++ < 4)     printf("  ");
      putchar(' ');
      i= 0;
      while (i++ < size)  putchar(isgraph(mpu->memory[addr + i - 1]) ? mpu->memory[addr + i - 1] : ' ');
      while (i++ < 4)     putchar(' ');
      printf(" %s\n", insn);
      addr += size;
    }
  return 2;
}


int main(int argc, char **argv)
{
  M6502 *mpu= M6502_new(0, 0, 0);
  int bTraps= 0;

  program= argv[0];

  if ((2 == argc) && ('-' != *argv[1]))
    {
      if ((!loadInterpreter(mpu, 0, argv[1])) && (!load(mpu, 0, argv[1])))
	pfail(argv[1]);
      doBtraps(0, 0, mpu);
    }
  else
    while (++argv, --argc > 0)
      {
	int n= 0;
	if      (!strcmp(*argv, "-B"))  bTraps= 1;
	else if (!strcmp(*argv, "-d"))	n= doDisassemble(argc, argv, mpu);
	else if (!strcmp(*argv, "-G"))	n= doGtrap(argc, argv, mpu);
	else if (!strcmp(*argv, "-h"))	n= doHelp(argc, argv, mpu);
	else if (!strcmp(*argv, "-i"))	n= doLoadInterpreter(argc, argv, mpu);
	else if (!strcmp(*argv, "-I"))	n= doIRQ(argc, argv, mpu);
	else if (!strcmp(*argv, "-l"))	n= doLoad(argc, argv, mpu);
	else if (!strcmp(*argv, "-M"))	n= doMtrap(argc, argv, mpu);
	else if (!strcmp(*argv, "-mc")) n= doMode(M6502_ModeCompiled);
	else if (!strcmp(*argv, "-mh")) n= doMode(M6502_ModeHybrid);
	else if (!strcmp(*argv, "-mi")) n= doMode(M6502_ModeInterpreted);
	else if (!strcmp(*argv, "-mx")) n= doMaxInsns(argc, argv, mpu);
	else if (!strcmp(*argv, "-N"))	n= doNMI(argc, argv, mpu);
	else if (!strcmp(*argv, "-P"))	n= doPtrap(argc, argv, mpu);
	else if (!strcmp(*argv, "-R"))	n= doRST(argc, argv, mpu);
	else if (!strcmp(*argv, "-s"))	n= doSave(argc, argv, mpu);
	else if (!strcmp(*argv, "-v"))	n= doVersion(argc, argv, mpu);
	else if (!strcmp(*argv, "-X"))	n= doXtrap(argc, argv, mpu);
	else if (!strcmp(*argv, "-x"))	exit(0);
	else if ('-' == **argv)		usage(1);
	else
	  {
	    /* doBtraps() left 0x8000+0x4000 in bank 0, so load */
	    /* additional images starting at 15 and work down */
	    static int bankSel= 0x0F;
	    if (!bTraps)			usage(1);
	    if (bankSel < 0)			fail("too many images");
	    if (!load(mpu, 0x8000, argv[0]))	pfail(argv[0]);
	    memcpy(bank[bankSel--],
		   0x8000 + mpu->memory,
		   0x4000);
	    n= 0;
	  }
	argc -= n;
	argv += n;
      }

  M6502_setMode(mpu, mode, max_insns);

  if (bTraps)
    doBtraps(0, 0, mpu);

  M6502_reset(mpu);
  M6502_run(mpu);
  M6502_delete(mpu);

  return 0;
}
