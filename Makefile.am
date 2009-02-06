AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

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


python: oftracemodule.so
oftrace_wrap.o: oftrace_wrap.c oftrace.i
	swig -python oftrace.i
	$(CC) $(CFLAGS) -I/usr/inlude/python2.5 -c $<
oftracemodule.so: liboftrace.a oftrace_wrap.o
	ld -shared $(subst .c,.o,$(liboftrace_a_SOURCES)) oftrace_wrap.o -o $@

count: 
	@wc -l $(ofstats_SOURCES) $(liboftrace_a_SOURCES) $(oftrace_SOURCES) | sort -n
