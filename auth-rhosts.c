/*

auth-rhosts.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 17 05:12:18 1995 ylo

Rhosts authentication.  This file contains code to check whether to admit
the login based on rhosts authentication.  This file also processes
/etc/hosts.equiv.

*/

/*
 * $Id: auth-rhosts.c,v 1.4 1995/07/27 00:37:00 ylo Exp $
 * $Log: auth-rhosts.c,v $
 * Revision 1.4  1995/07/27  00:37:00  ylo
 * 	Added /etc/hosts.equiv in quick test.
 *
 * Revision 1.3  1995/07/13  01:13:20  ylo
 * 	Removed the "Last modified" header.
 *
 * $Endlog$
 */

#include "includes.h"
#include "packet.h"
#include "ssh.h"
#include "xmalloc.h"

/* Returns true if the strings are equal, ignoring case (a-z only). */

static int casefold_equal(const char *a, const char *b)
{
  unsigned char cha, chb;
  for (; *a; a++, b++)
    {
      cha = *a;
      chb = *b;
      if (!chb)
	return 0;
      if (cha >= 'a' && cha <= 'z')
	cha -= 64;
      if (chb >= 'a' && chb <= 'z')
	chb -= 64;
      if (cha != chb)
	return 0;
    }
  return !*b;
}

/* Tries to authenticate the user using the .shosts or .rhosts file.  
   Returns true if authentication succeeds.  */

int auth_rhosts(struct passwd *pw, const char *client_user)
{
  struct sockaddr_in from;
  char buf[1024]; /* Note: must not be larger than host, user, dummy below. */
  const char *name;
  int port, fromlen, socket;
  FILE *f;
  struct stat st;
  static const char *rhosts_files[] = { ".shosts", ".rhosts", NULL };
  unsigned int rhosts_file_index;

  /* Quick check: if the user has no .shosts or .rhosts files, return failure
     immediately without doing costly lookups from name servers. */
  for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
       rhosts_file_index++)
    {
      /* Check users .rhosts or .shosts. */
      sprintf(buf, "%s/%s", pw->pw_dir, rhosts_files[rhosts_file_index]);
      if (stat(buf, &st) >= 0)
	break;
    }
  if (!rhosts_files[rhosts_file_index] && stat("/etc/hosts.equiv", &st) < 0)
    return 0; /* The user has no .shosts or .rhosts file. */

  /* Check that the connection comes from a privileged port. */

  /* Get the client socket. */
  socket = packet_get_connection();

  /* Get IP address of client. */
  fromlen = sizeof(from);
  if (getpeername(socket, (struct sockaddr *)&from, &fromlen) < 0)
    {
      error("getpeername failed");
      return 0;
    }
  
  /* Get the port number. */
  port = ntohs((u_short)from.sin_port);
  
  /* Check that it is a priviledged port.  rhosts authentication only makes
     sense for priviledged programs.  Of course, if the intruder has root
     access on his local machine, he can connect from any port.  So do not
     use .rhosts authentication from machines that you do not trust. */
  if (from.sin_family != AF_INET ||
      port >= IPPORT_RESERVED ||
      port < IPPORT_RESERVED/2)
    {
      log("Connection from %.100s from nonpriviledged port %d",
	  inet_ntoa(from.sin_addr), port);
      packet_send_debug("Your ssh client is not running as root.");
      return 0;
    }

  /* Ok, the connection is from a privileged port.  Get the name of the
     remote host. */
  name = get_canonical_hostname();

  /* If not superuser, local and remote users are the same, 
     try /etc/hosts.equiv. */
  if (pw->pw_uid != 0 && strcmp(pw->pw_name, client_user) == 0)
    { 
      /* Check /etc/hosts.equiv. */
      f = fopen("/etc/hosts.equiv", "r");
      if (f)
	{
	  while (fgets(buf, sizeof(buf), f))
	    {
	      if (strrchr(buf, '\n'))
		*strrchr(buf, '\n') = 0;
	      if (!buf[0] || buf[0] == ' ' || buf[0] == '\t')
		continue; /* Empty line or something strange. */
	      if (buf[0] == '#')
		continue; /* Some systems have comments in /etc/hosts.equiv. */
	      if (buf[0] == '+' || buf[0] == '-')
		continue; /* Eliminate the common Sun bug.  We do not support
			     NIS hosts.equiv or netgroups anyway. */
	      if (casefold_equal(buf, name))
		{
		  packet_send_debug("Authentication granted by /etc/hosts.equiv.");
		  return 1; /* Accepted by hosts.equiv. */
		}
	    }
	  fclose(f);
	}
    }

  /* Check that the home directory is owned by root or the user, and is not 
     group or world writable. */
  if (stat(pw->pw_dir, &st) < 0)
    {
      log("Rhosts authentication refused for %.100: no home directory %.200s",
	  pw->pw_name, pw->pw_dir);
      packet_send_debug("Rhosts authentication refused for %.100: no home directory %.200s",
			pw->pw_name, pw->pw_dir);
      return 0;
    }
  if ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
      (st.st_mode & 022) != 0)
    {
      log("Rhosts authentication refused for %.100s: bad ownership or modes for home directory.",
	  pw->pw_name);
      packet_send_debug("Rhosts authentication refused for %.100s: bad ownership or modes for home directory.",
			pw->pw_name);
      return 0;
    }
  
  /* Check all .rhosts files (currently .shosts and .rhosts). */
  for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
       rhosts_file_index++)
    {
      /* Check users .rhosts or .shosts. */
      sprintf(buf, "%s/%s", pw->pw_dir, rhosts_files[rhosts_file_index]);
      if (stat(buf, &st) < 0)
	continue; /* No such file. */

      /* Make sure that the file is either owned by the user or by root,
	 and make sure it is not writable by anyone but the owner.  This is
	 to help avoid novices accidentally allowing access to their account
	 by anyone. */
      if ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
	  (st.st_mode & 022) != 0)
	{
	  log("Rhosts authentication refused for %.100s: bad modes for %.200s",
	      pw->pw_name, buf);
	  packet_send_debug("Rhosts authentication refused for %.100s: bad modes for %.200s",
			    pw->pw_name, buf);
	  return 0;
	}
  
      /* Open the .rhosts file. */
      f = fopen(buf, "r");
      if (!f)
	{
	  packet_send_debug("Could not open %.900s for reading.", buf);
	  packet_send_debug("If your home is on an NFS volume, it may need to be world-readable.");
	  continue; /* Cannot read the .rhosts - deny access. */
	}

      /* Go through the .rhosts file, checking every entry. */
      while (fgets(buf, sizeof(buf), f))
	{
	  /* All three must be at least as big as buf to avoid overflows. */
	  char host[1024], user[1024], dummy[1024];

	  /* This should be safe because each buffer is as big as the whole
	     string, and thus cannot be overwritten. */
	  switch (sscanf(buf, "%s %s %s", host, user, dummy))
	    {
	    case 0:
	      packet_send_debug("Found empty line in %.100s",
				rhosts_files[rhosts_file_index]);
	      continue; /* Empty line? */
	    case 1:
	      /* Host name only. */
	      strncpy(user, pw->pw_name, sizeof(user));
	      user[sizeof(user) - 1] = 0;
	      break;
	    case 2:
	      /* Got both host and user name. */
	      break;
	    case 3:
	      packet_send_debug("Found garbage in %.100s",
				rhosts_files[rhosts_file_index]);
	      continue; /* Extra garbage */
	    default:
	      continue; /* Weird... */
	    }

	  if (host[0] == '+' || host[0] == '#')
	    {
	      packet_send_debug("Ignoring '+' or '#' lines in %.100s",
				rhosts_files[rhosts_file_index]);
	      continue; /* Ignore some potentially occurring wrong hostnames.*/
	    }
      
	  if (!casefold_equal(host, name) || strcmp(user, client_user) != 0)
	    continue; /* No match. */
	  
	  /* Authentication accepted by .rhosts. */
	  fclose(f);
	  packet_send_debug("Authentication accepted by %.100s",
			    rhosts_files[rhosts_file_index]);
	  return 1;
	}
      /* Authentication using this file denied. */
      fclose(f);
    }

  /* Rhosts authentication denied. */
  return 0;
}
