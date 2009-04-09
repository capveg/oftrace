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
dist_man_MANS = oftrace.3

# for now, don't put oftrace into it's own directory
# FYI: http://www.openismus.com/documents/linux/building_libraries/building_libraries.shtml
library_includedir=$(includedir)
library_include_HEADERS=oftrace.h

liboftrace_la_SOURCES= oftrace.c oftrace.h	\
		utils.c utils.h \
		tcp_session.c  tcp_session.h

ofdump_SOURCES = ofdump.c
ofdump_LDADD = liboftrace.la

ofstats_SOURCES = ofstats.c
ofstats_LDADD = liboftrace.la

pkgpython_PYTHON = oftrace.py __init__.py
pkgpyexec_LTLIBRARIES = _oftrace.la
_oftrace_la_SOURCES = oftrace_wrap_python.c oftrace.i
_oftrace_la_LDFLAGS = -module $(AM_LDFLAGS)
_oftrace_la_CFLAGS = $(SWIG_PYTHON_CPPFLAGS) $(AM_CFLAGS)
_oftrace_la_CPPFLAGS = $(SWIG_PYTHON_CPPFLAGS) $(AM_CFLAGS)
_oftrace_la_LIBADD = liboftrace.la

oftrace_wrap_python.c oftrace.py : oftrace.i
	$(SWIG) $(SWIG_PYTHON_OPT) $(AM_FLAGS) -o $<
#swig -python -module oftrace -o $@ $<	

count: 
	@wc -l $(ofstats_SOURCES) $(liboftrace_la_SOURCES) $(ofdump_SOURCES) | sort -n
