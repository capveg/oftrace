AUTOMAKE_OPTIONS=-Wall -Werror 
#SUBDIRS = policies

ACLOCAL_AMFLAGS = -I m4

OFSRC=@openflowsrc@

AM_CFLAGS = -Wall -Werror -g -O0 -I$(OFSRC)/include -I$(OFSRC)/lib
AM_LDFLAGS = -g -O0 -L$(OFSRC)/lib -lm

LDADD=$(OFSRC)/lib/libopenflow.a

#EXTRA_DIST = __init__.py oftrace.py
#bin_SCRIPTS = oftrace.py

bin_PROGRAMS=ofdump ofstats
lib_LTLIBRARIES=liboftrace.la
man_MANS = oftrace.3

# for now, don't put oftrace into it's own directory
# FYI: http://www.openismus.com/documents/linux/building_libraries/building_libraries.shtml
library_includedir=$(includedir)
library_include_HEADERS=oftrace.h

liboftrace_la_SOURCES= oftrace.c 	\
		utils.c \
		tcp_session.c

ofdump_SOURCES = ofdump.c
ofdump_LDADD = liboftrace.la

ofstats_SOURCES = ofstats.c
ofstats_LDADD = liboftrace.la

pkgpython_PYTHON = oftrace.py
pkgpyexec_LTLIBRARIES = _oftrace.la
_oftrace_la_SOURCES = oftrace_wrap_python.c oftrace.i
_oftrace_la_LDFLAGS = -module
_oftrace_la_CFLAGS = $(SWIG_PYTHON_CPPFLAGS)
_oftrace_la_CPPFLAGS = $(SWIG_PYTHON_CPPFLAGS)
_oftrace_la_LIBADD = liboftrace.la

oftrace_wrap_python.c oftrace.py : oftrace.i
	swig -python -module oftrace -o $@ $<	


pyoftrace_wrap.c: oftrace.i
	swig -python -o pyoftrace_wrap.c -module pyoftrace oftrace.i

count: 
	@wc -l $(ofstats_SOURCES) $(liboftrace_la_SOURCES) $(ofdump_SOURCES) | sort -n
