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

#ifndef FUNCTIONMANAGER_H
#define FUNCTIONMANAGER_H

#include <assert.h>
#include <boost/shared_ptr.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/utility.hpp>
#include <set>
#include <stdint.h>

#include "const.h"
#include "JitBool.h"
#include "lib6502.h"

class Function;

class FunctionManager : boost::noncopyable
{
public:
    FunctionManager(M6502 *mpu);
    ~FunctionManager();

    bool jit_thread_idle();

    void update_memory_snapshot();

    // Return a Function object representing the code starting at 'address'; if
    // one does not already exist it will be created. This never returns null.
    Function *get_function(uint16_t address)
    {
        Function *f = function_for_address_[address];
        if (f != 0)
        {
            return f;
        }
        else
        {
            return build_function(address, mpu_->memory);
        }
    }

    // Return a Function object representing the code starting at 'address',
    // if one is available, otherwise return null. When null is returned
    // a background thread may be used to generate a Function object which
    // can be returned if the request is repeated in the future.
    //
    // This function may only be called if the last call to jit_thread_idle()
    // returned true and no call has been made to get_function_lazy() since
    // jit_thread_idle() was called.
    //
    // Currently a background thread will *always* be invoked if null is
    // returned, but this is not guaranteed. For example, we may wish to
    // refuse to waste time building a Function object which we expect to
    // be invalidated by self-modifying code shortly afterwards.
    Function *get_function_lazy(uint16_t address)
    {
        // This assert() is perfectly correct, but it single-handedly destroys
        // the performance of a debug build; it's just not *that* valuable.
        // assert(jit_thread_idle());

        Function *f = function_for_address_[address];
        if (f != 0)
        {
            return f;
        }
        else
        {
            build_function_lazy(address);
            return 0;
        }
    }

    void code_modified_at(uint16_t address);

private:
    void add_function(const boost::shared_ptr<Function> &f);

    Function *build_function(uint16_t address, const uint8_t *ct_memory);
    Function *build_function_internal(uint16_t address, 
                                      const uint8_t *ct_memory);

    void build_function_lazy(uint16_t address);
    void build_function_thread();

    typedef std::set<Function *> FunctionSet;
    void destroy_functions_in_set(FunctionSet &function_set);

    void destroy_function(Function *f);

    boost::thread jit_thread_;

    boost::mutex jit_thread_idle_mutex_;
    bool jit_thread_idle_;

    boost::mutex jit_thread_cv_mutex_;
    boost::condition_variable jit_thread_cv_;
    bool work_available_;
    uint16_t jit_thread_address_;
    bool quit_;

    M6502 *mpu_;

    // A copy of the emulated CPU's memory, used to detect changes to already
    // JITted code which happen in callbacks and to avoid problems with JITting
    // while the interpreter is running (in hybrid mode).
    uint8_t memory_snapshot_[memory_size];

    // We maintain this array of shared_ptr's which actually own the
    // Function objects.
    boost::shared_ptr<Function> function_for_address_owner_[memory_size];

    // We maintain a parallel array of raw pointers here so that we have
    // the option to allow JITted code to access it.
    Function *function_for_address_[memory_size];

    // This tracks the Function objects which contain code generated based on
    // individual addresses, i.e. the Function objects which are invalidated by
    // a store to a given memory location.
    FunctionSet functions_covering_address_[memory_size];

    // This tracks the Function objects which perform optimistic writes to
    // individual addresses, i.e. the Function objects which are invalidated if
    // it turns out an address is in fact used to hold code.
    FunctionSet optimistic_writers_for_address_[memory_size];

    // This tracks whether we have ever executed code at a given address;
    // destroying all the functions in the corresponding element of
    // functions_covering_address does *not* mean this is cleared.
    JitBool code_at_address_[memory_size];
};

#endif
