AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

rundir = $(localstatedir)/run
AM_CFLAGS = -Wall -Werror -g -O0
AM_LDFLAGS = -g -O0

CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib
LDFLAGS+=-L$(OFSRC)/lib -lm

LDADD=$(OFSRC)/lib/libopenflow.a


bin_PROGRAMS=ofdump
lib_LIBRARIES=liboftrace.a

liboftrace_a_SOURCES= oftrace.c 	\
		utils.c \
		tcp_session.c

ofdump_SOURCES = ofdump.c
ofdump_LDADD = liboftrace.a

count: 
	@wc -l $(liboftrace_a_SOURCES) $(oftrace_SOURCES) | sort -n
