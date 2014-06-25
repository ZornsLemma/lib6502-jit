/* Copyright (c) 2014 Steven Flintham
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

#include "AddressRange.h"

#include <assert.h>

#include "const.h"

AddressRange::AddressRange(uint16_t addr)
: range_begin_(addr), range_end_(range_begin_ + 1)
{
}

AddressRange::AddressRange(uint32_t range_begin, uint32_t range_end)
: range_begin_(range_begin), range_end_(range_end)
{
    assert(range_begin_ < memory_size);
    assert(range_end_ <= (memory_size + 0xff));
    assert(range_begin_ < range_end_);
}

bool AddressRange::all_memory() const
{
    // This doesn't catch some degenerate cases (e.g. range_begin_ = 0x1,
    // range_end_ = 0x10002) but that doesn't matter.
    return (range_begin_ == 0) && (range_end_ == memory_size);
}
