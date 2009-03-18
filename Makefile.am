AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

rundir = $(localstatedir)/run
AM_CFLAGS = -Wall -Werror -pg
AM_LDFLAGS = -pg

CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib
LDFLAGS+=-L$(OFSRC)/lib -lm

LDADD=$(OFSRC)/lib/libopenflow.a


bin_PROGRAMS=oftrace

oftrace_SOURCES= oftrace.c 

count: 
	@wc -l $(oftrace_SOURCES) | sort -n
