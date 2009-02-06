#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

#include <net/ethernet.h>

#include "utils.h"



void * _realloc_and_check(void * ptr, size_t bytes, char * file, int lineno)
{
	void * ret = realloc(ptr,bytes);
	if(!ret)
	{
		perror("malloc/realloc: ");
		// use fprintf here in addition to flowvisor_err, incase we can't allocate the err msg buf
		fprintf(stderr, "Malloc/Realloc(%zu bytes) failed at %s:%d\n",bytes,file,lineno);
		abort();
	}
	return ret;
}

