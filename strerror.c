/*

strerror.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Mar 22 18:18:21 1995 ylo

Replacement for strerror for systems that don't have it.

*/

/* RCSID("$Id: strerror.c,v 1.2 1999/05/04 11:59:24 bg Exp $"); */

#include <stdio.h>
#include <errno.h>

extern int sys_nerr;
extern char *sys_errlist[];

char *strerror(int error_number)
{
  if (error_number >= 0 && error_number < sys_nerr)
    return sys_errlist[error_number];
  else
    return NULL;
}
