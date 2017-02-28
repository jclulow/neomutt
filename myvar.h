#ifndef MYVAR_INCLUDED
#define MYVAR_INCLUDED

#include <sys/types.h>

const char* myvar_get (const char* var);
int var_to_string (int idx, char* val, size_t len);
int mutt_option_index (char *s);

#endif

