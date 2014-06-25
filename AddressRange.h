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

// An AddressRange represents a contiguous range of addresses in the emulated
// memory, expressed as a half-open interval ("begin" is included, "end" is
// excluded). To allow convenient handling of cases where addresses wrap around
// at the top of memory, end may be as large as 0x100ff; this allows the
// effective address range of an instruction like LDA &ffff,Y to be represented.
// (The "largest" address accessed is &00fe, and since the interval is half-open
// end needs to allow a value one larger.)

#ifndef ADDRESSRANGE_H
#define ADDRESSRANGE_H

#include <stdint.h>

class AddressRange
{
public:
    // Convenience function; equivalent to AddressRange(addr, addr + 1) without
    // any need to worry about whether addr + 1 will wrap to 0.
    AddressRange(uint16_t addr);

    AddressRange(uint32_t range_begin, uint32_t range_end);

    uint32_t range_begin() const
    {
        return range_begin_;
    }

    uint32_t range_end() const
    {
        return range_end_;
    }

    // Return true iff AddressRange covers the whole of memory.
    bool all_memory() const;

    class const_iterator
    {
    friend class AddressRange;

    public:
        uint16_t operator*() const
        {
            // Truncating down to 16 bits gives exactly the behaviour we
            // require if this is a range which uses values >= 0x10000 to
            // indicate wrapping around to the start of memory.
            return static_cast<uint16_t>(v_);
        }

        const_iterator &operator++()
        {
            ++v_;
            return *this;
        }

        bool operator!=(const const_iterator &rhs)
        {
            return v_ != rhs.v_;
        }

    private:
        const_iterator(uint32_t v)
        : v_(v)
        {
        }

        uint32_t v_;
    };

    const_iterator begin() const
    {
        return const_iterator(range_begin_);
    }

    const_iterator end() const
    {
        return const_iterator(range_end_);
    }

private:
    uint32_t range_begin_;
    uint32_t range_end_;
};

#endif
