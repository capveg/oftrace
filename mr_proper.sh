#!/bin/sh
set -x
if [ -f Makefile ] ; then
	make maintainer-clean
fi

rm -rf aclocal.m4 configure depcomp install-sh missing Makefile.in autom4te.cache config.status Makefile config.log py-compile
rm -rf gmon.out

# stupid emacs users
rm -f *~
# swit wrapper
rm -f *_wrap_python.c config.guess config.sub ltmain.sh
rm -f oftrace.p*
