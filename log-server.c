/*

log-server.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:19:30 1995 ylo
Last modified: Mon Apr 24 14:51:26 1995 ylo

*/

#include "includes.h"
#include <syslog.h>
#include "packet.h"
#include "ssh.h"

static int log_debug = 0;
static int log_quiet = 0;
static int log_on_stderr = 0;

/* Initialize the log.
     av0	program name (should be argv[0])
     on_stderr	print also on stderr
     debug	send debugging messages to system log
     quiet	don\'t log anything
     */

void log_init(char *av0, int on_stderr, int debug, int quiet)
{
  log_debug = debug;
  log_quiet = quiet;
  log_on_stderr = on_stderr;
  closelog(); /* Close any previous log. */
  openlog(av0, LOG_PID, LOG_DAEMON);
}

/* Log this message (information that usually should go to the log). */

void log(const char *fmt, ...)
{
  char buf[1024];
  va_list args;
  if (log_quiet)
    return;
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "%s\n", buf);
  syslog(LOG_INFO, "%s", buf);
}

/* Debugging messages that should not be logged during normal operation. */

void debug(const char *fmt, ...)
{
  char buf[1024];
  va_list args;
  if (!log_debug || log_quiet)
    return;
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "%s\n", buf);
  syslog(LOG_DEBUG, "%s", buf);
}

/* Error messages that should be logged. */

void error(const char *fmt, ...)
{
  char buf[1024];
  va_list args;
  if (log_quiet)
    return;
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "%s\n", buf);
  syslog(LOG_ERR, "%s", buf);
}

/* Fatal messages.  This function never returns. */

void fatal(const char *fmt, ...)
{
  char buf[1024];
  va_list args;
  if (log_quiet)
    exit(1);
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "%s\n", buf);
  syslog(LOG_NOTICE, "%s", buf);

  /* Unlink any X11 sockets if necessary. */
  channel_stop_listening();

  /* Close the connection to the client. */
  packet_close();

  exit(1);
}
