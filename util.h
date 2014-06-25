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

#ifndef UTIL_H
#define UTIL_H

#include <assert.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#define CANT_HAPPEN(s) \
    do { \
        std::stringstream stream; \
        stream << __FILE__ << ":" << __LINE__ << ":" << s; \
        throw std::runtime_error(stream.str()); \
    } \
    while (false)

#ifdef LOG
    #define TRACE(s) \
        do { \
            std::stringstream prefix; \
            prefix << __FILE__ << ":" << __LINE__ << "\t" <<  \
                      boost::this_thread::get_id() << "\t"; \
            std::stringstream message; \
            message << s; \
            log(apply_prefix(prefix.str(), message.str())); \
        } \
        while (false)
#else
    #define TRACE(s) \
        do { \
        } \
        while (false)
#endif

// Avoid spurious "unused variable" warnings from regular assert().
#ifndef NDEBUG
    #define ASSERT_EQUAL(x, y) assert((x) == (y))
#else
    #define ASSERT_EQUAL(x, y) \
        do { \
            x = x; \
        } \
        while (0);
#endif

extern boost::mutex log_mutex;
void log(const std::string &s);
void die(const char *s);

std::string spaces(int n);
std::string apply_prefix(const std::string &prefix, const std::string &s);

#endif
