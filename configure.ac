# 
# Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior
# University
# 
# We are making the OpenFlow specification and associated documentation
# (Software) available for public use and benefit with the expectation
# that others will use, modify and enhance the Software and contribute
# those enhancements back to the community. However, since we would
# like to make the Software available for broadest use, with as few
# restrictions as possible permission is hereby granted, free of charge,
# to any person obtaining a copy of this Software to deal in the Software
# under the copyrights without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
# NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# 
# The name and trademarks of copyright holder(s) may NOT be used in
# advertising or publicity pertaining to the Software or any derivatives
# without specific, written prior permission.

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([oftrace], [0.4], [rob.sherwood@stanford.edu])
AM_INIT_AUTOMAKE([-Wall -Werror ])
AC_CONFIG_SRCDIR([.])
#AC_CONFIG_HEADERS([])



AC_DEFUN([OPENFLOWSRC_DEFAULT],[`pwd`/../openflow])


dnl Give option to change location of openflow directory
AC_ARG_WITH(openflow-src-dir,
        [  --with-openflow-src-dir=PATH    Specify path to OpenFlow Source Directory (default: OPENFLOWSRC_DEFAULT) ],
	[ 
		case "$withval" in
			# Relative paths
			./*|../*)       withval="`pwd`/$withval"
		esac
		if test "x$withval" = "x" ; then
			AC_MSG_ERROR([--with-openflow-src-dir needs an argument],[1])
		fi
		OPENFLOWSRC=$withval
	 ],
	[OPENFLOWSRC=OPENFLOWSRC_DEFAULT]
)

dnl Make sure we have the openflow source somewhere
AC_CHECK_FILE(
	[$OPENFLOWSRC/include/openflow/openflow.h],
	[],
	[AC_MSG_ERROR(
		[Could not find openflow source at $OPENFLOWSRC -- please install]
		,[1])
	])

dnl Define $(openflowsrc) in makefile
AC_SUBST([openflowsrc],$OPENFLOWSRC)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_LIBTOOL

# ??? automake told me to add this..
AM_PROG_CC_C_O

#custom
LARGE_FILES

dnl Enable swig support
AC_ARG_ENABLE(swig,
	[AS_HELP_STRING([--disable-swig],
			[disable SWIG (default is enabled)])],
	[case "${enableval}" in
		(yes) enable_swig=true ;;
		(no)  enable_swig=false ;;
		(*) AC_MSG_ERROR([bad value ${enableval} for --enable-swig]) ;;
		esac],
	[enable_swig=true])
if test "$enable_swig" = true; then
   AC_PYTHON_DEVEL
   AC_PROG_SWIG(1.3.0)
   if test -z "$SWIG"; then
	  AC_MSG_ERROR([swig 1.3.0 or later required - please install])
   fi
   AM_PATH_PYTHON(2.5)
   SWIG_PYTHON
else
   AC_MSG_NOTICE([SWIG support has been disabled])
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([config.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([malloc/malloc.h])
AC_CHECK_HEADERS([features.h])

# Check for necessary defines
AC_CHECK_DECLS([[ETH_ALEN]], [], [], [[#include <net/ethernet.h>]])
AC_CHECK_DECLS([[ETHER_ADDR_LEN]],
	[if test "$ac_cv_have_decl_eth_alen" != yes ; then
	        AC_DEFINE([ETH_ALEN], [ETHER_ADDR_LEN])
	fi],
	[if test "$ac_cv_have_decl_eth_alen" != yes ; then
	        AC_MSG_ERROR([neither ETH_ALEN or ETH_ADDR_LEN are defined])
	fi],
	[[#include <net/ethernet.h>]])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strerror])


AC_CONFIG_FILES([Makefile oftrace.i])

AC_OUTPUT
