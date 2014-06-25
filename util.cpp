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

#include "util.h"

#include <boost/thread/thread.hpp>
#include <iostream>
#include <stdio.h>

boost::mutex log_mutex;

void log(const std::string &s)
{
    boost::mutex::scoped_lock scoped_lock(log_mutex);
    std::cerr << s << std::endl;
}

void die(const char *s)
{
  fflush(stdout);
  fprintf(stderr, "\n%s\n", s);
  abort();
}

std::string spaces(int n)
{
    return std::string(4 * n, ' ');
}

std::string apply_prefix(const std::string &prefix, const std::string &s)
{
    std::string result = prefix;
    for (std::string::size_type i = 0; i < s.length(); ++i)
    {
        result += s[i];
        if ((s[i] == '\n') && ((i + 1) < s.length()))
        {
            result.append(prefix);
        }
    }
    return result;
}

