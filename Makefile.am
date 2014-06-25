ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = `$(LLVMCONFIG) --cppflags` $(BOOST_CPPFLAGS)
# lib6502.c generates spurious warnings with -Wall, so we want -Wno-parentheses
# too. It's not easy to have per-source-file build flags in automake, so we
# just apply this to all C files.
AM_CFLAGS = -Wall -Wno-parentheses
AM_CXXFLAGS = `$(LLVMCONFIG) --cxxflags` -fexceptions -Wall
AM_LDFLAGS = $(BOOST_THREAD_LDFLAGS)
LIBS = `$(LLVMCONFIG) --ldflags --libs core jit native --system-libs` $(BOOST_THREAD_LIBS)

# Some of these are included automatically, but I'd rather be explicit.
EXTRA_DIST = \
	examples/README \
	COPYING \
	CREDITS \
	lib6502-compatibility.txt \
	README \
	README.lib6502 \
	TODO \
	man/* \
	test/*.xa \
	test/*.mst \
	test/run-c-tests.sh \
	test/run-run6502-tests.sh \
	test/run-c-tests.py \
	test/run-run6502-tests.py

man1_MANS = man/*.1
man3_MANS = man/*.3
lib_LTLIBRARIES = lib6502-jit.la
include_HEADERS = lib6502.h
bin_PROGRAMS = run6502
noinst_PROGRAMS = \
	examples/lib1
check_PROGRAMS = \
	test/basic-callback \
	test/call-illegal-callback-modify-code \
	test/irq-nmi \
	test/setjmp-trick \
	test/stack-code-brk \
	test/stack-code-jsr \
	test/write-callback-modify-code

lib6502_jit_la_SOURCES = \
	AddressRange.cpp \
	AddressRange.h \
	AddressSet.cpp \
	AddressSet.h \
	const.h \
	Function.cpp \
	Function.h \
	FunctionBuilder.cpp \
	FunctionBuilder.h \
	FunctionManager.cpp \
	FunctionManager.h \
	JitBool.h \
	lib6502.c \
	lib6502.h \
	lib6502-jit.cpp \
	LLVMStuff.cpp \
	LLVMStuff.h \
	M6502Internal.h \
	Registers.cpp \
	Registers.h \
	util.cpp \
	util.h \
	valgrind.h

run6502_SOURCES = \
	run6502.c
run6502_LINK = $(CXXLINK)
run6502_LDADD = lib6502-jit.la

examples_lib1_SOURCES = \
	examples/lib1.c
examples_lib1_LINK = $(CXXLINK)
examples_lib1_LDADD = lib6502-jit.la

test_basic_callback_SOURCES = \
	test/basic-callback.c \
	test/test-utils.c \
	test/test-utils.h
test_basic_callback_LINK = $(CXXLINK)
test_basic_callback_LDADD = lib6502-jit.la

test_call_illegal_callback_modify_code_SOURCES = \
	test/call-illegal-callback-modify-code.c \
	test/test-utils.c \
	test/test-utils.h
test_call_illegal_callback_modify_code_LINK = $(CXXLINK)
test_call_illegal_callback_modify_code_LDADD = lib6502-jit.la

test_irq_nmi_SOURCES = \
	test/irq-nmi.c \
	test/test-utils.c \
	test/test-utils.h
test_irq_nmi_LINK = $(CXXLINK)
test_irq_nmi_LDADD = lib6502-jit.la

test_setjmp_trick_SOURCES = \
	test/setjmp-trick.c \
	test/test-utils.c \
	test/test-utils.h
test_setjmp_trick_LINK = $(CXXLINK)
test_setjmp_trick_LDADD = lib6502-jit.la

test_stack_code_brk_SOURCES = \
	test/stack-code-brk.c \
	test/test-utils.c \
	test/test-utils.h
test_stack_code_brk_LINK = $(CXXLINK)
test_stack_code_brk_LDADD = lib6502-jit.la

test_stack_code_jsr_SOURCES = \
	test/stack-code-jsr.c \
	test/test-utils.c \
	test/test-utils.h
test_stack_code_jsr_LINK = $(CXXLINK)
test_stack_code_jsr_LDADD = lib6502-jit.la

test_write_callback_modify_code_SOURCES = \
	test/write-callback-modify-code.c \
	test/test-utils.c \
	test/test-utils.h
test_write_callback_modify_code_LINK = $(CXXLINK)
test_write_callback_modify_code_LDADD = lib6502-jit.la

TESTS = \
	test/run-c-tests.sh \
	test/run-run6502-tests.sh
