/*

fd-check-2.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Apr 23 19:37:57 1995 ylo

Prints "yes" if file descriptor 25 is valid, "no" otherwise.

*/

/*
 * $Id: fd-check-2.c,v 1.2 1995/07/13 01:23:26 ylo Exp $
 * $Log: fd-check-2.c,v $
 * Revision 1.2  1995/07/13  01:23:26  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include <stdio.h>
#include <fcntl.h>

int main(int ac, char **av)
{
  if (fcntl(25, F_GETFL, NULL) < 0)
    printf("no\n");
  else
    printf("yes\n");
  exit(0);
}
