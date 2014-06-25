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

#include "FunctionManager.h"

#include <functional>

#include "Function.h"
#include "FunctionBuilder.h"
#include "M6502Internal.h"
#include "Registers.h"
#include "util.h"

FunctionManager::FunctionManager(M6502 *mpu)
: jit_thread_idle_(true), work_available_(false), quit_(false), mpu_(mpu), 
  memory_snapshot_(), function_for_address_(), code_at_address_()
{
}

FunctionManager::~FunctionManager()
{
    if (jit_thread_.get_id() != boost::thread::id())
    {
        TRACE("Notifying JIT thread to quit");
        {
            boost::mutex::scoped_lock lock(jit_thread_cv_mutex_);
            quit_ = true;
        }
        jit_thread_cv_.notify_all();
        TRACE("Joining with JIT thread");
        jit_thread_.join();
    }
}

bool FunctionManager::jit_thread_idle()
{
    boost::mutex::scoped_lock lock(jit_thread_idle_mutex_);
    return jit_thread_idle_;
}

void FunctionManager::update_memory_snapshot()
{
    assert(jit_thread_idle());

    const uint8_t *memory = mpu_->memory;
    for (size_t i = 0; i < memory_size; ++i)
    {
        if (code_at_address_[i] && (memory_snapshot_[i] != memory[i]))
        {
            code_modified_at(i);
        }
        memory_snapshot_[i] = memory[i];
    }
}

Function *FunctionManager::build_function_internal(
    uint16_t address, const uint8_t *ct_memory)
{
    Registers &registers = mpu_->internal->registers_;
    TRACE("Building Function for code at 0x" << std::hex << std::setfill('0') <<
          std::setw(4) << registers.pc);
    FunctionBuilder fb(mpu_, ct_memory, code_at_address_, registers.pc);
    boost::shared_ptr<Function> f(fb.build());
    add_function(f);
    return f.get();
}

Function *FunctionManager::build_function(uint16_t address, 
                                          const uint8_t *ct_memory)
{
    Function *f;
    int pass = 0;
    do
    {
        assert(pass < 2);
        ++pass;

        f = build_function_internal(address, ct_memory);

        bool f_is_optimistic_self_writer = false;
        const AddressSet &code_range = f->code_range();
        for (AddressSet::const_iterator it = code_range.begin();
             it != code_range.end(); ++it)
        {
            uint16_t i = *it;
            if (code_at_address_[i] && 
                !optimistic_writers_for_address_[i].empty())
            {
                // There is now code at an address where optimistic writes are
                // performed. Future code generation won't create optimistic
                // writes there because code_at_address_[i] has now been set,
                // but we need to destroy existing functions which perform
                // that write so they will be regenerated.
                const FunctionSet &optimistic_writers = 
                    optimistic_writers_for_address_[i];
                f_is_optimistic_self_writer = 
                    (optimistic_writers.find(f) != optimistic_writers.end());
                destroy_functions_in_set(optimistic_writers_for_address_[i]);
                if (f_is_optimistic_self_writer)
                {
                    // destroy_functions_in_set() has now destroyed f, so a)
                    // code_range is no longer a valid reference b) there's
                    // no need to continue iterating over f's code range.
                    break;
                }

            }
        }

        // We might just have destroyed the function we built, if it modified
        // its own code, so we need to loop round if so.
        f = function_for_address_[address];
        if (f == 0)
        {
            assert(f_is_optimistic_self_writer);
            TRACE("Rebuilding just-created function");
        }
    }
    while (f == 0);

    TRACE(f->dump_all());

    return f;
}

void FunctionManager::build_function_lazy(uint16_t address)
{
    assert(jit_thread_idle());

    TRACE("Will build Function for address 0x" << std::hex << 
          std::setfill('0') << std::setw(4) << address << " in background");

    // We only create the JIT thread the first time it's needed; this avoids it
    // existing if the library is being used in interpreted or compiled mode.
    if (jit_thread_.get_id() == boost::thread::id())
    {
        TRACE("Creating JIT thread");
        boost::thread t(
            std::mem_fun(&FunctionManager::build_function_thread), this);
        jit_thread_.swap(t);
    }

    {
        boost::mutex::scoped_lock lock(jit_thread_idle_mutex_);
        jit_thread_idle_ = false;
    }
    {
        boost::mutex::scoped_lock lock(jit_thread_cv_mutex_);
        work_available_ = true;
        jit_thread_address_ = address;
    }
    jit_thread_cv_.notify_all();
}

void FunctionManager::build_function_thread()
{
    try
    {
        TRACE("JIT thread started");
        boost::mutex::scoped_lock jit_thread_cv_mutex_lock(
            jit_thread_cv_mutex_);
        while (true)
        {
            while (!quit_ && !work_available_)
            {
                TRACE("JIT thread waiting to be signalled");
                jit_thread_cv_.wait(jit_thread_cv_mutex_lock);
            }

            if (quit_)
            {
                TRACE("JIT thread quitting");
                return;
            }
            else
            {
                TRACE("JIT thread about to build Function at address 0x" <<
                      std::hex << std::setfill('0') << std::setw(4) << 
                      jit_thread_address_);
                assert(work_available_);
                assert(!jit_thread_idle_);

                // Note that we translate code from memory_snapshot_
                // not mpu_->memory. This is important, even though we
                // have update_memory_snapshot() which "should" invalidate
                // Function objects which depend on modified code before any
                // of them are used. The reason is that if a memory location
                // is temporarily modified by the interpreter before it can
                // be translated, then modified back to its original value
                // by the interpreter before update_memory_snapshot() is
                // called, update_memory_snapshot() can't notice the change,
                // but the change has been compiled into the Function object.
                // (See test/z-self-modify-2.xa; this breaks in hybrid mode
                // if memory_snapshot_ isn't used here.)
                build_function(jit_thread_address_, memory_snapshot_);
                work_available_ = false;

                boost::mutex::scoped_lock jit_thread_idle_lock(
                    jit_thread_idle_mutex_);
                jit_thread_idle_ = true;
            }
        }
    }
    catch (std::exception &e)
    {
        die(e.what());
    }
}

void FunctionManager::add_function(const boost::shared_ptr<Function> &f)
{
    function_for_address_[f->address()] = f.get();
    function_for_address_owner_[f->address()] = f;

    const AddressSet &code_range = f->code_range();
    for (AddressSet::const_iterator it = code_range.begin(); 
         it != code_range.end(); ++it)
    {
        uint16_t i = *it;
        functions_covering_address_[i].insert(f.get());
        code_at_address_[i] = true;
    }

    const AddressSet &optimistic_writes = f->optimistic_writes();
    for (AddressSet::const_iterator it = optimistic_writes.begin();
         it != optimistic_writes.end(); ++it)
    {
        uint16_t i = *it;
        optimistic_writers_for_address_[i].insert(f.get());
    }
}

void FunctionManager::code_modified_at(uint16_t address)
{
    // We could just return immediately if code_at_address_[address] is false;
    // sometimes we call this function without bothering to check first.
    // In practice I doubt this has a significant impact on performance.

    TRACE("Code modified at 0x" << std::hex << std::setfill('0') << 
          std::setw(4) << address);

    destroy_functions_in_set(functions_covering_address_[address]);

    // Keep memory_snapshot_ up-to-date; this avoids harmless-but-inefficient
    // destruction of perfectly valid Function objects when
    // update_memory_snapshot() is called next.
    memory_snapshot_[address] = mpu_->memory[address];
}

void FunctionManager::destroy_functions_in_set(FunctionSet &function_set)
{
    // We iterate over the set like this because destroy_function() will erase
    // the function from function_set, thereby invalidating any iterator we are
    // holding on to.
    while (!function_set.empty())
    {
        destroy_function(*function_set.begin());
    }
}

void FunctionManager::destroy_function(Function *f)
{
    const AddressSet &code_range = f->code_range();
    for (AddressSet::const_iterator it = code_range.begin(); 
         it != code_range.end(); ++it)
    {
        uint16_t i = *it;
        size_t erased_count = functions_covering_address_[i].erase(f);
        ASSERT_EQUAL(erased_count, 1);
        // We do *not* clear code_at_address_[i] even if
        // functions_covering_address_[i] is now empty; this records the fact
        // that we have executed code at this address. This is critical for
        // the current implementation of build_function(); code_at_address_
        // being set is used to control optimistic vs non-optimistic writes,
        // and if code_at_address_ was cleared when a function was destroyed
        // a self-modifying function would cause an infinite loop inside
        // build_function(). It would be OK to clear code_at_address_ for any
        // addresses with empty functions_covering_address_ sets at the end
        // of build_function(), but we currently don't.
    }

    const AddressSet &optimistic_writes = f->optimistic_writes();
    for (AddressSet::const_iterator it = optimistic_writes.begin();
         it != optimistic_writes.end(); ++it)
    {
        uint16_t i = *it;
        size_t erased_count = optimistic_writers_for_address_[i].erase(f);
        ASSERT_EQUAL(erased_count, 1);
    }

    assert(function_for_address_[f->address()] == f);
    function_for_address_[f->address()] = 0;
    // Do this last as it will cause the Function object to be deleted.
    assert(function_for_address_owner_[f->address()].get() == f);
    function_for_address_owner_[f->address()].reset();
}
