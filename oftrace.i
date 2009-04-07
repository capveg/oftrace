/* Attempt to swig'ify liboftrace */

%module oftrace
%{ 
#include "oftrace.h"
%}

// take care of unsupported uint types
%apply unsigned int { uint32_t }
%apply unsigned short { uint16_t }


// Parse the header file
%include "oftrace.h"


