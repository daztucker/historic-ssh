/*

match.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Thu Jun 22 01:17:50 1995 ylo

Simple pattern matching, with '*' and '?' as wildcards.

*/

/*
 * $Id: match.c,v 1.4 1998/06/11 00:07:36 kivinen Exp $
 * $Log: match.c,v $
 * Revision 1.4  1998/06/11 00:07:36  kivinen
 * 	Added match_user function.
 *
 * Revision 1.3  1997/04/27  22:19:35  kivinen
 * 	Fixed typo.
 *
 * Revision 1.2  1997/04/27 21:52:05  kivinen
 * 	Added F-SECURE stuff. Added match_port function.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.2  1995/07/13  01:27:07  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "ssh.h"
#include "xmalloc.h"

/* Returns true if the given string matches the pattern (which may contain
   ? and * as wildcards), and zero if it does not match. */
	  
int match_pattern(const char *s, const char *pattern)
{
  while (1)
    {
      /* If at end of pattern, accept if also at end of string. */
      if (!*pattern)
        return !*s;

      /* Process '*'. */
      if (*pattern == '*')
        {
	  /* Skip the asterisk. */
	  pattern++;

	  /* If at end of pattern, accept immediately. */
          if (!*pattern)
            return 1;

	  /* If next character in pattern is known, optimize. */
          if (*pattern != '?' && *pattern != '*')
            {
	      /* Look instances of the next character in pattern, and try
		 to match starting from those. */
              for (; *s; s++)
                if (*s == *pattern &&
                    match_pattern(s + 1, pattern + 1))
                  return 1;
	      /* Failed. */
              return 0;
            }

	  /* Move ahead one character at a time and try to match at each
	     position. */
          for (; *s; s++)
            if (match_pattern(s, pattern))
              return 1;
	  /* Failed. */
          return 0;
        }

      /* There must be at least one more character in the string.  If we are
	 at the end, fail. */
      if (!*s)
        return 0;

      /* Check if the next character of the string is acceptable. */
      if (*pattern != '?' && *pattern != *s)
	return 0;
      
      /* Move to the next character, both in string and in pattern. */
      s++;
      pattern++;
    }
  /*NOTREACHED*/
}

/* this combines the effect of match_pattern on a username, hostname
   and IP address. If the pattern contains a @ then the part preceding
   the @ is checked against the username. The part after the @ is
   checked against the hostname and IP address. If no @ is found then
   a normal match_pattern is done against the username 

   This is more useful than just a match_pattern as it allows you to
   specify exactly what users are alowed to login from what hosts
   (tridge, May 1998)
*/
int match_user(const char *user, const char *host, const char *ip,
	       const char *pattern)
{
  int ret;
  char *p2;
  char *p;

  p = strchr(pattern,'@');
  
  if (!p)
    return match_pattern(user, pattern);

  p2 = xstrdup(pattern);
  p = strchr(p2, '@');
  
  *p = 0;

  ret = match_pattern(user,p2) && 
    (match_pattern(host, p+1) || match_pattern(ip, p+1));
  
  xfree(p2);
  return ret;
 }

#ifdef F_SECURE_COMMERCIAL








































































#endif /* F_SECURE_COMMERCIAL */
