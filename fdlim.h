/*

fdlim.h

Author: David Mazieres <dm@lcs.mit.edu>
	Contributed to be part of ssh.

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Tue Aug 22 17:21:32 1995 ylo

*/

/*
 * $Log: fdlim.h,v $
 * Revision 1.1.1.1  1996/02/18 21:38:11  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.4  1995/09/06  15:59:56  ylo
 * 	Added support for machines that don't have RLIM_INFINITY.
 *
 * Revision 1.3  1995/08/31  09:21:14  ylo
 * 	Fixed processing of RLIMIT_INFINITY on systems with 64 bit
 * 	resource limits.
 *
 * Revision 1.2  1995/08/29  22:22:38  ylo
 * 	Ported into ssh source tree.
 *
 * Revision 1.1  1995/08/22  14:24:46  ylo
 * 	Initial version from David Mazieres.
 *
 * $EndLog$
 */

#ifndef FDLIM_H
#define FDLIM_H

static int
fdlim_get (int hard)
{
#ifdef RLIMIT_NOFILE
  struct rlimit rlfd;
  if (getrlimit (RLIMIT_NOFILE, &rlfd) < 0)
    return (-1);
#ifdef RLIM_INFINITY /* not defined on HPSUX */
  if ((hard ? rlfd.rlim_max : rlfd.rlim_cur) == RLIM_INFINITY)
    return 10000;
  else
    return hard ? rlfd.rlim_max : rlfd.rlim_cur;
#else /* RLIM_INFINITY */
  return hard ? rlfd.rlim_max : rlfd.rlim_cur;
#endif /* RLIM_INFINITY */
#else /* !RLIMIT_NOFILE */
#ifdef HAVE_GETDTABLESIZE
  return (getdtablesize ());
#else /* !HAVE_GETDTABLESIZE */
#ifdef _SC_OPEN_MAX
  return (sysconf (_SC_OPEN_MAX));
#else /* !_SC_OPEN_MAX */
#ifdef NOFILE
  return (NOFILE);
#else /* !NOFILE */
  return (25);
#endif /* !NOFILE */
#endif /* !_SC_OPEN_MAX */
#endif /* !HAVE_GETDTABLESIZE */
#endif /* !RLIMIT_NOFILE */
}

static int
fdlim_set (int lim) {
#ifdef RLIMIT_NOFILE
  struct rlimit rlfd;
  if (lim <= 0)
    return (-1);
  if (getrlimit (RLIMIT_NOFILE, &rlfd) < 0)
    return (-1);
  rlfd.rlim_cur = lim;
  if (setrlimit (RLIMIT_NOFILE, &rlfd) < 0)
    return (-1);
  return (0);
#else /* !RLIMIT_NOFILE */
  return (-1);
#endif /* !RLIMIT_NOFILE */
}

#endif /* FDLIM_H */
