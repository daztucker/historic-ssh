/*

fd-check-1.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Apr 23 19:33:07 1995 ylo
Last modified: Sun Apr 23 19:54:22 1995 ylo

This program is used by configure to check if shells close all file
descriptors on this system.  This works by creating desciptor 25, and executes
the given command.  See also fd-check-2.c.

*/

#include <stdio.h>

int main(int ac, char **av)
{
  if (ac < 2)
    {
      fprintf(stderr, "%s: too few arguments\n", av[0]);
      exit(1);
    }
  if (dup2(0, 25) < 0)
    {
      fprintf(stderr, "%s: dup2 failed\n", av[0]);
      exit(1);
    }
  execvp(av[1], av + 1);
  fprintf(stderr, "%s: execvp %s failed\n", av[0], av[1]);
  exit(1);
}
