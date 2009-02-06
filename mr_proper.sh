#!/bin/sh
set -x
if [ -f Makefile ] ; then
	make maintainer-clean
fi
rm -rf aclocal.m4 configure depcomp install-sh missing Makefile.in autom4te.cache config.status Makefile config.log
rm -rf gmon.out
# stupid emacs users
rm -f *~
