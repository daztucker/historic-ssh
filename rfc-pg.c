/*

rfc-pg.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@ssh.fi>, Espoo, Finland
Copyright (c) 1995-1999 SSH Communications Security Oy, Espoo, Finland
                        All rights reserved

Created: Fri Jul  7 02:14:16 1995 ylo

*/

/*
 * $Id: rfc-pg.c,v 1.2 1999/11/17 17:04:52 tri Exp $
 * $Log: rfc-pg.c,v $
 * Revision 1.2  1999/11/17 17:04:52  tri
 * 	Fixed copyright notices.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:10  ylo
 *      Imported ssh-1.2.13.
 *
 * Revision 1.2  1995/07/13  01:31:15  ylo
 *      Removed "Last modified" header.
 *      Added cvs log.
 *
 * $Endlog$
 */

#include <stdio.h>

int main()
{
  int add_formfeed = 0;
  int skipping = 0;
  int ch;

  while ((ch = getc(stdin)) != EOF)
    {
      if (ch == '\n')
        {
          if (add_formfeed)
            {
              putc('\n', stdout);
              putc('\014', stdout);
              putc('\n', stdout);
              add_formfeed = 0;
              skipping = 1;
              continue;
            }
          if (skipping)
            continue;
        }
      skipping = 0;
      if (ch == '\014')
        {
          add_formfeed = 1;
          continue;
        }
      putc(ch, stdout);
    }
  exit(0);
}
