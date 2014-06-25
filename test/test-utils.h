/* test-utils.h -- utility functions for C test programs */

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

#ifndef PARSEARGS_H
#define PARSEARGS_H

#include "lib6502.h"

void parse_args(int argc, char *argv[], M6502 *mpu);

void M6502_dump_masked(M6502 *mpu, char buffer[64]);

#endif
