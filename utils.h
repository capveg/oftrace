#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>

#include "openflow/openflow.h"

// sigh.. why is this not defined in some standard place
#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#define CONFIG_GUEST_SUFFIX	".guest"
#define CONFIG_SWITCH_SUFFIX	".switch"

#define malloc_and_check(x) _realloc_and_check(NULL,(x),__FILE__,__LINE__);
#define realloc_and_check(ptr,x) _realloc_and_check((ptr),(x),__FILE__,__LINE__);
void * _realloc_and_check(void * ptr,size_t bytes, char * file, int lineno);

#endif
