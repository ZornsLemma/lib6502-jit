AC_INIT([lib6502-jit], [1.0], [lib6502-jit@lemma.co.uk])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects no-dist-gzip dist-bzip2])
AM_MAINTAINER_MODE([enable])
LT_INIT([disable-shared])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Copyright for configure.ac *only*
AC_COPYRIGHT([Copyright (c) 2014 Steven Flintham])

AC_DEFINE([PACKAGE_COPYRIGHT], ["(C) - see COPYING"], [Package copyright])

# for tap-driver.sh
AC_PROG_AWK

AC_PROG_CC
AC_PROG_CXX

BOOST_REQUIRE
BOOST_SMART_PTR
BOOST_THREAD

# I want to:
# - use "llvm-config" (relying on PATH) if the user doesn't do anything 
#   special, but
# - allow the user to say --with-llvm-config=XXX to use XXX instead of 
#   llvm-config, where XXX might need to be found on the PATH (e.g. if 
#   the program is called llvm-config-3.5) or might be an absolute/
#   relative filename
# In both of the above cases, I want to actually check explicitly the 
# llvm-config program can be found. This doesn't seem to be supported by 
# autoconf:
# - AC_CHECK_PROG() and AC_PATH_PROG() both insist on the program name being a 
#   leaf name with no included path.
# - AC_CHECK_FILE() (not unreasonably) doesn't look on PATH for the file
#   (and wouldn't check for executability)
# So I have to just hack it with "which" and hope.
AC_ARG_WITH(
	[llvm-config], 
	[AS_HELP_STRING(
		[--with-llvm-config=FILE], 
		[filename of llvm-config executable (if not on PATH)])], 
	[LLVMCONFIG="$withval"], 
	[LLVMCONFIG="llvm-config"])
echo -n "checking for $LLVMCONFIG... "
AS_IF(
	[which "$LLVMCONFIG" >/dev/null],
	[echo yes],
	[echo no
	 AC_MSG_ERROR([llvm-config not found; try --with-llvm-config=FILE?])])

AC_SUBST(LLVMCONFIG)

# These variables are sacred to the user. But we need to set them in order for
# configure's test programs to find the LLVM headers. I am probably doing this
# completely wrong. In twenty years or so maybe I will achieve auto-enlightenment
# and look back at this and laugh.
SACRED_CPPFLAGS="$CPPFLAGS"
SACRED_CXXFLAGS="$CXXFLAGS"

CPPFLAGS=["`$LLVMCONFIG --cppflags` $CPPFLAGS"]
CXXFLAGS=["`$LLVMCONFIG --cxxflags` -fexceptions $CXXFLAGS"]

AC_LANG(C++)

# This header moves around a bit, check for the two known possible locations.

AC_CHECK_HEADER(
	[llvm/IR/Verifier.h], 
	[AC_DEFINE([HAVE_LLVM_IR_VERIFIER_H], 1, [Set to 1 if you have the "llvm/IR/Verifier.h" header file])])
AC_CHECK_HEADER(
	[llvm/Analysis/Verifier.h], 
	[AC_DEFINE([HAVE_LLVM_ANALYSIS_VERIFIER_H], 1, [Set to 1 if you have the "llvm/Analysis/Verifier.h" header file])])
# TODO: Can I get configure to fail if neither of the previous tests
# succeeds? Otherwise configure will succeed but the build will fail.

# This header always exists, but DataLayoutPass isn't always present.
AC_CHECK_HEADER(
	[llvm/IR/DataLayout.h],
	[],
	[AC_MSG_ERROR([llvm/IR/DataLayout.h not found])])
AC_CHECK_TYPE(
	[llvm::DataLayoutPass],
	[AC_DEFINE([HAVE_LLVM_DATA_LAYOUT_PASS], 1, [Set to 1 if you have the llvm::DataLayoutPass class])],
	[],
	[#include "llvm/IR/DataLayout.h"])

CPPFLAGS="$SACRED_CPPFLAGS"
CXXFLAGS="$SACRED_CXXFLAGS"

AC_OUTPUT
