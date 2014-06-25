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

#include "AddressSet.h"

#include <assert.h>
#include <sstream>
#include <stddef.h>

#include "AddressRange.h"
#include "util.h"

void AddressSet::insert(uint16_t address)
{
    set_.insert(address);
}

void AddressSet::insert(const AddressRange &range)
{
    for (AddressRange::const_iterator it = range.begin(); it != range.end(); 
         ++it)
    {
        set_.insert(*it);
    }
}

namespace
{
    std::string dump_range(uint32_t range_start, uint32_t range_end)
    {
        std::stringstream s;
        s << std::hex << std::setfill('0');
        if ((range_start + 1) == range_end)
        {
            s << "0x" << std::setw(4) << range_start;
        }
        else
        {
            // It's probably more readable to dump in this (inclusive) format
            // than to insist on using the half-open intervals which are
            // "natural" in the code itself.
            s << "0x" << std::setw(4) << range_start << "-" <<
                 "0x" << std::setw(4) << (range_end - 1);
        }
        return s.str();
    }
}

std::string AddressSet::dump(int indent) const
{
    std::stringstream s;

    bool in_range = false;
    uint32_t range_start;
    uint32_t range_last;
    for (AddressSet::const_iterator it = set_.begin(); it != set_.end(); ++it)
    {
        uint16_t i = *it;
        if (!in_range)
        {
            range_start = i;
            range_last = i;
            in_range = true;
        }
        else
        {
            if (i != (range_last + 1))
            {
                s << spaces(indent) << 
                     dump_range(range_start, range_last + 1) << "\n";
                range_start = i;
            }
            range_last = i;
        }
    }
    if (in_range)
    {
        s << spaces(indent) << dump_range(range_start, range_last + 1) << "\n";
    }
    return s.str();
}
