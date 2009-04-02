AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

ACLOCAL_AMFLAGS = -I m4

OFSRC=@openflowsrc@

rundir = $(localstatedir)/run
AM_CFLAGS = -Wall -Werror -g -O0
AM_LDFLAGS = -g -O0

CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib
LDFLAGS+=-L$(OFSRC)/lib -lm

LDADD=$(OFSRC)/lib/libopenflow.a


bin_PROGRAMS=ofdump ofstats
lib_LIBRARIES=liboftrace.a

liboftrace_a_SOURCES= oftrace.c 	\
		utils.c \
		tcp_session.c

ofdump_SOURCES = ofdump.c
ofdump_LDADD = liboftrace.a

ofstats_SOURCES = ofstats.c
ofstats_LDADD = liboftrace.a


python: _pyoftrace.so
pyoftrace_wrap.c: oftrace.i
	swig -python -o pyoftrace_wrap.c -module pyoftrace oftrace.i
pyoftrace_wrap.o: pyoftrace_wrap.c 
	$(CC) $(CFLAGS) -I/usr/include/python2.5 -c $<
_pyoftrace.so: liboftrace.a pyoftrace_wrap.o
	ld -shared $(subst .c,.o,$(liboftrace_a_SOURCES)) pyoftrace_wrap.o -o $@

count: 
	@wc -l $(ofstats_SOURCES) $(liboftrace_a_SOURCES) $(ofdump_SOURCES) | sort -n
