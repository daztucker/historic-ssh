/*

log-server.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:19:30 1995 ylo

Server-side versions of debug(), log(), etc.  These normally send the output
to the system log.

*/

/*
 * $Id: log-server.c,v 1.5 1995/10/02 01:22:57 ylo Exp $
 * $Log: log-server.c,v $
 * Revision 1.5  1995/10/02  01:22:57  ylo
 * 	Include sys/syslog.h if needed.
 *
 * Revision 1.4  1995/09/09  21:26:42  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.3  1995/08/21  23:25:00  ylo
 * 	Added support for syslog facility.
 *
 * Revision 1.2  1995/07/13  01:26:21  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
#include "packet.h"
#include "xmalloc.h"
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

void log_init(char *av0, int on_stderr, int debug, int quiet, 
	      SyslogFacility facility)
{
  int log_facility;
  
  switch (facility)
    {
    case SYSLOG_FACILITY_DAEMON:
      log_facility = LOG_DAEMON;
      break;
    case SYSLOG_FACILITY_USER:
      log_facility = LOG_USER;
      break;
    case SYSLOG_FACILITY_AUTH:
      log_facility = LOG_AUTH;
      break;
    case SYSLOG_FACILITY_LOCAL0:
      log_facility = LOG_LOCAL0;
      break;
    case SYSLOG_FACILITY_LOCAL1:
      log_facility = LOG_LOCAL1;
      break;
    case SYSLOG_FACILITY_LOCAL2:
      log_facility = LOG_LOCAL2;
      break;
    case SYSLOG_FACILITY_LOCAL3:
      log_facility = LOG_LOCAL3;
      break;
    case SYSLOG_FACILITY_LOCAL4:
      log_facility = LOG_LOCAL4;
      break;
    case SYSLOG_FACILITY_LOCAL5:
      log_facility = LOG_LOCAL5;
      break;
    case SYSLOG_FACILITY_LOCAL6:
      log_facility = LOG_LOCAL6;
      break;
    case SYSLOG_FACILITY_LOCAL7:
      log_facility = LOG_LOCAL7;
      break;
    default:
      fprintf(stderr, "Unrecognized internal syslog facility code %d\n",
	      (int)facility);
      exit(1);
    }

  log_debug = debug;
  log_quiet = quiet;
  log_on_stderr = on_stderr;
  closelog(); /* Close any previous log. */
  openlog(av0, LOG_PID, log_facility);
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
    fprintf(stderr, "log: %s\n", buf);
  syslog(LOG_INFO, "log: %.500s", buf);
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
    fprintf(stderr, "debug: %s\n", buf);
  syslog(LOG_DEBUG, "debug: %.500s", buf);
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
    fprintf(stderr, "error: %s\n", buf);
  syslog(LOG_ERR, "error: %.500s", buf);
}

struct fatal_cleanup
{
  struct fatal_cleanup *next;
  void (*proc)(void *);
  void *context;
};

static struct fatal_cleanup *fatal_cleanups = NULL;

/* Registers a cleanup function to be called by fatal() before exiting. */

void fatal_add_cleanup(void (*proc)(void *), void *context)
{
  struct fatal_cleanup *cu;

  cu = xmalloc(sizeof(*cu));
  cu->proc = proc;
  cu->context = context;
  cu->next = fatal_cleanups;
  fatal_cleanups = cu;
}

/* Removes a cleanup frunction to be called at fatal(). */

void fatal_remove_cleanup(void (*proc)(void *context), void *context)
{
  struct fatal_cleanup **cup, *cu;
  
  for (cup = &fatal_cleanups; *cup; cup = &cu->next)
    {
      cu = *cup;
      if (cu->proc == proc && cu->context == context)
	{
	  *cup = cu->next;
	  xfree(cu);
	  return;
	}
    }
  fatal("fatal_remove_cleanup: no such cleanup function: 0x%lx 0x%lx\n",
	(unsigned long)proc, (unsigned long)context);
}

/* Fatal messages.  This function never returns. */

void fatal(const char *fmt, ...)
{
  char buf[1024];
  va_list args;
  struct fatal_cleanup *cu, *next_cu;
  static int fatal_called = 0;

  if (log_quiet)
    exit(1);
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "fatal: %s\n", buf);
  syslog(LOG_ERR, "fatal: %.500s", buf);

  if (fatal_called)
    exit(1);
  fatal_called = 1;

  /* Call cleanup functions. */
  for (cu = fatal_cleanups; cu; cu = next_cu)
    {
      next_cu = cu->next;
      debug("Calling cleanup 0x%lx(0x%lx)",
	    (unsigned long)cu->proc, (unsigned long)cu->context);
      (*cu->proc)(cu->context);
    }

  exit(1);
}
