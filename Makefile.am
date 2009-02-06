AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

rundir = $(localstatedir)/run
AM_CFLAGS = -Wall -Werror -pg
AM_LDFLAGS = -pg

CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib
LDFLAGS+=-L$(OFSRC)/lib -lm

LDADD=$(OFSRC)/lib/libopenflow.a


bin_PROGRAMS=ofdump
lib_LIBRARIES=oftrace.a

oftrace_SOURCES= oftrace.c 	\
		utils.c \
		tcp_session.c

ofdump_SOURCES = ofdump.c
ofdump_LDADD = oftrace.a

count: 
	@wc -l $(oftrace_SOURCES) | sort -n
