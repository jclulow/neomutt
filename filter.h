#ifndef FILTER_INCLUDED
#define FILTER_INCLUDED

#include <unistd.h>
#include <stdio.h>

pid_t
mutt_create_filter_fd (const char *cmd, FILE **in, FILE **out, FILE **err,
                       int fdin, int fdout, int fderr);
pid_t mutt_create_filter (const char *s, FILE **in, FILE **out, FILE **err);
int mutt_wait_filter (pid_t pid);

#endif

