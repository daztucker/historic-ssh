/*

signals.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Jan 19 18:09:37 1995 ylo

Manipulation of signal state.  This file also contains code to set the
maximum core dump size.

*/

/*
 * $Log: signals.c,v $
 * Revision 1.2  1996/04/26 00:25:48  ylo
 * 	Test for SIGURG == SIGIO (which appears to be the case on some
 * 	Linux versions).
 *
 * Revision 1.1.1.1  1996/02/18 21:38:11  ylo
 * 	Imported ssh-1.2.13.
 *
 * $EndLog$
 */

#include "includes.h"
#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#endif /* HAVE_SETRLIMIT */

#ifndef NSIG
#define NSIG 100
#endif

unsigned long original_core_limit;

static RETSIGTYPE signal_handler(int sig)
{
  fprintf(stderr, "\nReceived signal %d.\n", sig);
  exit(255);
}

/* Sets signal handlers so that core dumps are prevented.  This also
   sets the maximum core dump size to zero as an extra precaution (where
   supported).  The old core dump size limit is saved. */

void signals_prevent_core()
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    switch (sig)
      {
      case SIGSTOP:
      case SIGTSTP:
      case SIGCONT:
      case SIGCHLD:
      case SIGTTIN:
      case SIGTTOU:
      case SIGIO:
#if defined(SIGURG) && SIGURG != SIGIO
      case SIGURG:
#endif
#ifdef SIGWINCH
      case SIGWINCH:
#endif
#ifdef SIGINFO
      case SIGINFO:
#endif
	signal(sig, SIG_DFL);
	break;
      default:
	signal(sig, signal_handler);
	break;
      }

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    original_core_limit = rl.rlim_cur;
    rl.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}

/* Sets all signals to their default state.  Restores RLIMIT_CORE previously
   saved by prevent_core(). */

void signals_reset()
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    signal(sig, SIG_DFL);

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = original_core_limit;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}
