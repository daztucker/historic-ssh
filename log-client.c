/*

log-client.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:13:40 1995 ylo

Client-side versions of debug(), log(), etc.  These print to stderr.

*/

/*
 * $Id: log-client.c,v 1.3 1995/08/21 23:24:44 ylo Exp $
 * $Log: log-client.c,v $
 * Revision 1.3  1995/08/21  23:24:44  ylo
 * 	Added support for log_quiet.
 *
 * Revision 1.2  1995/07/13  01:25:51  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "ssh.h"

static int log_debug = 0;
static int log_quiet = 0;

void log_init(char *av0, int on_stderr, int debug, int quiet,
	      SyslogFacility facility)
{
  log_debug = debug;
  log_quiet = quiet;
}

void log(const char *fmt, ...)
{
  va_list args;

  if (log_quiet)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void debug(const char *fmt, ...)
{
  va_list args;
  if (log_quiet || !log_debug)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void error(const char *fmt, ...)
{
  va_list args;
  if (log_quiet)
    return;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}

/* fatal() is in ssh.c so that it can properly reset terminal modes. */
