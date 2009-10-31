AUTOMAKE_OPTIONS=-Wall -Werror 
#SUBDIRS = policies

ACLOCAL_AMFLAGS = -I m4

OFSRC=@openflowsrc@

AM_CFLAGS = -Wall -I$(OFSRC)/include -I$(OFSRC)/lib  @LARGEFILES_CFLAGS@
AM_LDFLAGS = -L$(OFSRC)/lib -lm  @LARGEFILES_LDFLAGS@

LDADD=$(OFSRC)/lib/libopenflow.a

bin_SCRIPTS=pyofdump.py pyofstats.py lldp_stats.py
# should be redundant... but isn't for some reason :-(
EXTRA_DIST = $(bin_SCRIPTS)
bin_PROGRAMS=ofdump ofstats unittest
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
ofdump_LDFLAGS = -static
ofdump_LDADD = ./liboftrace.la

ofstats_SOURCES = ofstats.c
ofstats_LDFLAGS = -static
ofstats_LDADD = ./liboftrace.la

unittest_SOURCES = unittest.c
unittest_LDFLAGS = -static
unittest_LDADD = ./liboftrace.la

pkgpython_PYTHON = __init__.py
nodist_pkgpython_PYTHON=oftrace.py
pkgpyexec_LTLIBRARIES = _oftrace.la
_oftrace_la_SOURCES = oftrace_wrap_python.c oftrace.i 
_oftrace_la_LDFLAGS = -module $(AM_LDFLAGS)
_oftrace_la_CFLAGS = $(SWIG_PYTHON_CPPFLAGS) $(AM_CFLAGS)
_oftrace_la_CPPFLAGS = $(SWIG_PYTHON_CPPFLAGS) $(AM_CFLAGS)
_oftrace_la_LIBADD = ./liboftrace.la

oftrace_wrap_python.c: oftrace.i
	swig -python -module oftrace -o $@ $<	
#	$(SWIG) $(SWIG_PYTHON_OPT) $(AM_FLAGS) -o $<

count: 
	@wc -l $(ofstats_SOURCES) $(liboftrace_la_SOURCES) $(ofdump_SOURCES) | sort -n
