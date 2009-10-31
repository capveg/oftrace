#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcp_session.h"

int main(int argc, char * argv[])
{
	assert(unittest_do_tcp_session_delete());
	return 0;
}
