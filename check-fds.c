/*

check-fds.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Apr  8 00:25:04 1995 ylo

*/

/*
 * $Id: check-fds.c,v 1.2 1995/07/13 01:19:38 ylo Exp $
 * $Log: check-fds.c,v $
 * Revision 1.2  1995/07/13  01:19:38  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int ac, char **av)
{
  int i, dummy;
  struct stat st;

  for (i = 0; i < 1024; i++)
    if (fcntl(i, F_GETFL, &dummy) >= 0)
      {
	printf("Descriptor %d is open.\n", i);
	if (fstat(i, &st) < 0)
	  perror("fstat");
	else
	  {
	    printf("st_mode 0x%x, st_dev 0x%x, st_rdev 0x%x, st_ino 0x%x, st_size 0x%lx\n",
		   st.st_mode, st.st_dev, st.st_rdev, st.st_ino, 
		   (long)st.st_size);
	    if (ttyname(i))
	      printf("ttyname: %s\n", ttyname(i));
	  }
      }
  exit(0);
}

