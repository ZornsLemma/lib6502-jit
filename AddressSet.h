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

#ifndef ADDRESSSET_H
#define ADDRESSSET_H

#include <set>
#include <stdint.h>
#include <string>

class AddressRange;

class AddressSet
{
private:
    // This might not be the perfect representation, but it's simple and clean,
    // so let's stick with it unless profiling shows this is a problem.
    typedef std::set<uint16_t> Container;

public:
    AddressSet()
    {
    }

    void insert(uint16_t address);

    void insert(const AddressRange &range);

    typedef Container::const_iterator const_iterator;

    const_iterator begin() const
    {
        return set_.begin();
    }

    const_iterator end() const
    {
        return set_.end();
    }

    Container::size_type size() const
    {
        return set_.size();
    }

    std::string dump(int indent) const;

private:
    std::set<uint16_t> set_;
};

#endif
