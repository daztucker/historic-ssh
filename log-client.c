/*

log-client.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:13:40 1995 ylo
Last modified: Wed Apr 19 16:53:55 1995 ylo

*/

#include "includes.h"
#include "ssh.h"

static int log_debug = 0;

void log_init(char *av0, int on_stderr, int debug, int quiet)
{
  log_debug = debug;
  /* Note that quiet is ignored because this implementation does not
     send anything to the syslog. */
}

void log(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void debug(const char *fmt, ...)
{
  va_list args;
  if (!log_debug)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void error(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

/* fatal() is in ssh.c so that it can properly reset terminal modes. */
