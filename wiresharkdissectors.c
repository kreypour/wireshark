#include "wiresharkdissectors.h"

int dissect(const char* input, char* output)
{
   memcpy(output, input, strlen(input));
   return 0;
}