/*

minfd.c

Author: David Mazieres <dm@lcs.mit.edu>
	Contributed to be part of ssh.

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Tue Aug 22 17:25:30 1995 ylo
Last modified: Tue Aug 22 20:19:33 1995 ylo

*/

/*
 * $Log: minfd.c,v $
 * Revision 1.2  1995/08/29  22:32:33  ylo
 * 	Ported to ssh source tree.
 *
 * Revision 1.1  1995/08/22  14:26:22  ylo
 * 	Initial version from David Mazieres.
 *
 * $EndLog$
 */

#include "includes.h"
#include <sys/resource.h> /* Needed by fdlim.h */
#include "fdlim.h"
#include "minfd.h"

#ifdef _PATH_BSHELL
#define DEFAULT_SHELL           _PATH_BSHELL
#else
#define DEFAULT_SHELL           "/bin/sh"
#endif

static int
_get_permanent_fd(const char *shellpath)
{
  const char *shell;
  struct passwd *pwd;
  int fdmin;
  int fdlim;
  int fd;
  int i;

  if (!shellpath) 
    {
      if ((pwd = getpwuid(getuid())))
	shellpath = pwd->pw_shell;
      if (!shellpath)
	shellpath = DEFAULT_SHELL;
    }
  if ((shell = strrchr(shellpath, '/')))
    shell++;
  else
    shell = shellpath;
  
  for (i = 0; strcmp(mafd[i].shell, shell); i++)
    if (i == MAFD_MAX - 1)
      return -1;

  fdmin = mafd[i].fd;
  fdlim = fdlim_get(0);
  
  if (fdmin < fdlim) 
    {
      /* First try to find a file descriptor as high as possible without
	 upping the limit */
      fd = fdlim - 1;
      while (fd >= fdmin)
	{
	  if (fcntl(fd, F_GETFL, NULL) < 0)
	    return fd;
	  fd--;
	}
    }

  fd = fdlim;
  for (;;) 
    {
      if (fdlim_set(fd + 1) < 0)
	return -1;
      if (fcntl(fd, F_GETFL, NULL) < 0)
	return fd;
      fd++;
    }
  return fd;
}

int
get_permanent_fd(const char *shellpath)
{
  static int fd = -2;

  if (fd >= -1)
    return fd;
  fd = _get_permanent_fd(shellpath);
  if (fd < 0)
    fd = -1;
  return fd;
}