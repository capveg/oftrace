#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([oftrace], [0.3], [rob.sherwood@stanford.edu])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
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

dnl check whether python extension is enabled and accordingly set swig
#m4_pattern_allow(AC_PROG_SWIG)
if test -n "$PYTHON"; then
   AC_PROG_SWIG(1.3.0)
   if test -z "$SWIG"; then
	  AC_MSG_ERROR([swig 1.3.0 or later required - please install])
   fi
   AM_PATH_PYTHON(2.5)
   SWIG_ENABLE_CXX
   SWIG_PYTHON
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([config.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strerror])


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
