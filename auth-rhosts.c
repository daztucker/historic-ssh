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
 * $Id: auth-rhosts.c,v 1.10 1998/07/08 00:38:32 kivinen Exp $
 * $Log: auth-rhosts.c,v $
 * Revision 1.10  1998/07/08 00:38:32  kivinen
 * 	Fixed typo (privileged).
 *
 * Revision 1.9  1998/05/23  20:20:04  kivinen
 * 	Added num_deny_shosts/num_allow_shosts option support.
 *
 * Revision 1.8  1998/04/30  03:58:38  kivinen
 * 	Fixed typo.
 *
 * Revision 1.7  1998/04/30 01:50:40  kivinen
 * 	Added parsing of comments in the end of any lind.
 *
 * Revision 1.6  1998/03/27 16:55:50  kivinen
 * 	Added check that .rhosts / .shosts cannot contain control
 * 	characters. Added ignore_root_rhosts support. Fixed .*hosts
 * 	ALLOW_GROUP_WRITEABLITY support.
 *
 * Revision 1.5  1997/03/26 06:59:58  kivinen
 * 	Changed uid 0 to UID_ROOT.
 *
 * Revision 1.4  1997/03/19 15:59:07  kivinen
 * 	Limit hostname and username to 255 characters.
 *
 * Revision 1.3  1996/10/29 22:34:25  kivinen
 * 	log -> log_msg.
 *
 * Revision 1.2  1996/02/18 21:53:00  ylo
 * 	Eliminate warning for innetgr arguments.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:13  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.11  1995/10/02  01:19:18  ylo
 * 	Fixed a serious security bug in the new hosts.equiv code.
 * 	Fixed case-insensitivity in host names.
 * 	Added support for /etc/shosts.equiv.
 *
 * Revision 1.10  1995/09/27  02:11:07  ylo
 * 	Ignore "NO_PLUS".
 * 	Fixed comment processing.
 *
 * Revision 1.9  1995/09/22  22:24:51  ylo
 * 	Removed some debugging calls that revealed too much
 * 	information.
 * 	Support negative entries and netgroups in /etc/hosts.equiv and
 * 	rhosts/shosts.
 *
 * Revision 1.8  1995/09/21  17:07:42  ylo
 * 	Added uidswap.h.
 * 	Restructured rhosts authentication code.  hosts.equiv now uses
 * 	the same code to process the file; user names are now
 * 	permitted in hosts.equiv.
 *
 * Revision 1.7  1995/09/09  21:26:37  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.6  1995/08/29  22:18:18  ylo
 * 	Permit using ip addresses in .rhosts and .shosts files.
 *
 * Revision 1.5  1995/08/22  14:05:16  ylo
 * 	Added uid-swapping.
 *
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
#include "userfile.h"
#include "servconf.h"

extern ServerOptions options;

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
	cha -= 32;
      if (chb >= 'a' && chb <= 'z')
	chb -= 32;
      if (cha != chb)
	return 0;
    }
  return !*b;
}

/* This function processes an rhosts-style file (.rhosts, .shosts, or
   /etc/hosts.equiv).  This returns true if authentication can be granted
   based on the file, and returns zero otherwise.  All I/O will be done
   using the given uid with userfile. */

int check_rhosts_file(uid_t uid, const char *filename, const char *hostname,
		      const char *ipaddr, const char *client_user,
		      const char *server_user)
{
  UserFile uf;
  char buf[1024]; /* Must not be larger than host, user, dummy below. */
  
  /* Open the .rhosts file. */
  uf = userfile_open(uid, filename, O_RDONLY, 0);
  if (uf == NULL)
    return 0; /* Cannot read the .rhosts - deny access. */

  /* Go through the file, checking every entry. */
  while (userfile_gets(buf, sizeof(buf), uf))
    {
      /* All three must be at least as big as buf to avoid overflows. */
      char hostbuf[1024], userbuf[1024], dummy[1024], *host, *user, *cp, *c;
      int negated;
      
      for(cp = buf; *cp; cp++)
	{
	  if (*cp < 32 && !isspace(*cp))
	    {
	      packet_send_debug("Found control characters in the .rhosts or .shosts file, rest of the file ignored");
	      userfile_close(uf);
	      return 0;
	    }
	}
      for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
	;
      if ((c = strchr(cp, '#')) != NULL)
	*c = '\0';
      if (*cp == '#' || *cp == '\n' || !*cp)
	continue;

      /* NO_PLUS is supported at least on OSF/1.  We skip it (we don't ever
	 support the plus syntax). */
      if (strncmp(cp, "NO_PLUS", 7) == 0)
	continue;

      /* This should be safe because each buffer is as big as the whole
	 string, and thus cannot be overwritten. */
      switch (sscanf(buf, "%s %s %s", hostbuf, userbuf, dummy))
	{
	case 0:
	  packet_send_debug("Found empty line in %.100s.", filename);
	  continue; /* Empty line? */
	case 1:
	  /* Host name only. */
	  strncpy(userbuf, server_user, sizeof(userbuf));
	  userbuf[sizeof(userbuf) - 1] = 0;
	  break;
	case 2:
	  /* Got both host and user name. */
	  break;
	case 3:
	  packet_send_debug("Found garbage in %.100s.", filename);
	  continue; /* Extra garbage */
	default:
	  continue; /* Weird... */
	}

      host = hostbuf;
      user = userbuf;
      /* Truncate host and user name to 255 to avoid buffer overflows in system
	 libraries */
      if (strlen(host) > 255)
	host[255] = '\0';
      if (strlen(user) > 255)
	user[255] = '\0';
      negated = 0;

      /* Process negated host names, or positive netgroups. */
      if (host[0] == '-')
	{
	  negated = 1;
	  host++;
	}
      else
	if (host[0] == '+')
	  host++;

      if (user[0] == '-')
	{
	  negated = 1;
	  user++;
	}
      else
	if (user[0] == '+')
	  user++;

      /* Check for empty host/user names (particularly '+'). */
      if (!host[0] || !user[0])
	{ 
	  /* We come here if either was '+' or '-'. */
	  packet_send_debug("Ignoring wild host/user names in %.100s.",
			    filename);
	  continue;
	}
	  
#ifdef HAVE_INNETGR

      /* Verify that host name matches. */
      if (host[0] == '@')
	{
	  if (!innetgr(host + 1, (char *)hostname, NULL, NULL) &&
	      !innetgr(host + 1, (char *)ipaddr, NULL, NULL))
	    continue;
	}
      else
	if (!casefold_equal(host, hostname) && strcmp(host, ipaddr) != 0)
	  continue; /* Different hostname. */

      /* Verify that user name matches. */
      if (user[0] == '@')
	{
	  if (!innetgr(user + 1, NULL, (char *)client_user, NULL))
	    continue;
	}
      else
	if (strcmp(user, client_user) != 0)
	  continue; /* Different username. */

#else /* HAVE_INNETGR */

      if (!casefold_equal(host, hostname) && strcmp(host, ipaddr) != 0)
	continue; /* Different hostname. */

      if (strcmp(user, client_user) != 0)
	continue; /* Different username. */

#endif /* HAVE_INNETGR */
      
      /* Check whether this host is permitted to be in .[rs]hosts. */
      {
	int perm_denied = 0;
	int i;
	if (options.num_deny_shosts > 0)
	  {
	    for (i = 0; i < options.num_deny_shosts; i++)
	      if (match_pattern(host, options.deny_shosts[i]))
		perm_denied = 1;
	  }
	if ((!perm_denied) && options.num_allow_shosts > 0)
	  {
	    for (i = 0; i < options.num_allow_shosts; i++)
	      if (match_pattern(host, options.allow_shosts[i]))
		break;
	    if (i >= options.num_allow_shosts)
	      perm_denied = 1;
	  }
	if (perm_denied)
	  {
	    log_msg("Use of %s denied for %s", filename, host);
	    continue;
	  }
      }

      /* Found the user and host. */
      userfile_close(uf);

      /* If the entry was negated, deny access. */
      if (negated)
	{
	  packet_send_debug("Matched negative entry in %.100s.",
			    filename);
	  return 0;
	}

      /* Accept authentication. */
      return 1;
    }
     
  /* Authentication using this file denied. */
  userfile_close(uf);
  return 0;
}

/* Tries to authenticate the user using the .shosts or .rhosts file.  
   Returns true if authentication succeeds.  If ignore_rhosts is
   true, only /etc/hosts.equiv will be considered (.rhosts and .shosts
   are ignored), unless the user is root and ignore_root_rhosts isn't
   true. */

int auth_rhosts(struct passwd *pw, const char *client_user,
		int ignore_rhosts, int ignore_root_rhosts,
		int strict_modes)
{
  char buf[1024];
  const char *hostname, *ipaddr;
  int port;
  struct stat st;
  static const char *rhosts_files[] = { ".shosts", ".rhosts", NULL };
  unsigned int rhosts_file_index;

  /* Quick check: if the user has no .shosts or .rhosts files, return failure
     immediately without doing costly lookups from name servers. */
  for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
       rhosts_file_index++)
    {
      /* Check users .rhosts or .shosts. */
      sprintf(buf, "%.500s/%.100s", 
	      pw->pw_dir, rhosts_files[rhosts_file_index]);
      if (userfile_stat(pw->pw_uid, buf, &st) >= 0)
	break;
    }

  if (!rhosts_files[rhosts_file_index] && 
      userfile_stat(pw->pw_uid, "/etc/hosts.equiv", &st) < 0 &&
      userfile_stat(pw->pw_uid, SSH_HOSTS_EQUIV, &st) < 0)
    return 0; /* The user has no .shosts or .rhosts file and there are no
		 system-wide files. */

  /* Get the name, address, and port of the remote host.  */
  hostname = get_canonical_hostname();
  ipaddr = get_remote_ipaddr();
  port = get_remote_port();

  /* Check that the connection comes from a privileged port.
     Rhosts authentication only makes sense for privileged programs.
     Of course, if the intruder has root access on his local machine,
     he can connect from any port.  So do not use .rhosts
     authentication from machines that you do not trust. */
  if (port >= IPPORT_RESERVED ||
      port < IPPORT_RESERVED / 2)
    {
      log_msg("Connection from %.100s from nonprivileged port %d",
	  hostname, port);
      packet_send_debug("Your ssh client is not running as root.");
      return 0;
    }

  /* If not logging in as superuser, try /etc/hosts.equiv and shosts.equiv. */
  if (pw->pw_uid != UID_ROOT)
    {
      if (check_rhosts_file(geteuid(), 
			    "/etc/hosts.equiv", hostname, ipaddr, client_user,
			    pw->pw_name))
	{
	  packet_send_debug("Accepted for %.100s [%.100s] by /etc/hosts.equiv.",
			    hostname, ipaddr);
	  return 1;
	}
      if (check_rhosts_file(geteuid(),
			    SSH_HOSTS_EQUIV, hostname, ipaddr, client_user,
			    pw->pw_name))
	{
	  packet_send_debug("Accepted for %.100s [%.100s] by %.100s.", 
			    hostname, ipaddr, SSH_HOSTS_EQUIV);
	  return 1;
	}
    }

  /* Check that the home directory is owned by root or the user, and is not 
     group or world writable. */
  if (userfile_stat(pw->pw_uid, pw->pw_dir, &st) < 0)
    {
      log_msg("Rhosts authentication refused for %.100: no home directory %.200s",
	  pw->pw_name, pw->pw_dir);
      packet_send_debug("Rhosts authentication refused for %.100: no home directory %.200s",
			pw->pw_name, pw->pw_dir);
      return 0;
    }
  if (strict_modes && 
      ((st.st_uid != UID_ROOT && st.st_uid != pw->pw_uid) ||
#ifdef ALLOW_GROUP_WRITEABILITY
       (st.st_mode & 002) != 0)
#else
       (st.st_mode & 022) != 0)
#endif
      )
    {
      log_msg("Rhosts authentication refused for %.100s: bad ownership or modes for home directory.",
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
      sprintf(buf, "%.500s/%.100s", 
	      pw->pw_dir, rhosts_files[rhosts_file_index]);
      if (userfile_stat(pw->pw_uid, buf, &st) < 0)
	continue; /* No such file. */

      /* Make sure that the file is either owned by the user or by root,
	 and make sure it is not writable by anyone but the owner.  This is
	 to help avoid novices accidentally allowing access to their account
	 by anyone. */
      if (strict_modes &&
	  ((st.st_uid != UID_ROOT && st.st_uid != pw->pw_uid) ||
	   (st.st_mode & 022) != 0))
	{
	  log_msg("Rhosts authentication refused for %.100s: bad modes for %.200s",
	      pw->pw_name, buf);
	  packet_send_debug("Bad file modes for %.200s", buf);
	  continue;
	}

      /* Check if we have been configured to ignore .rhosts and .shosts 
	 files.  If root, check ignore_root_rhosts first. */
      if ((pw->pw_uid == UID_ROOT && ignore_root_rhosts) ||
	  (pw->pw_uid != UID_ROOT && ignore_rhosts))
	{
	  packet_send_debug("Server has been configured to ignore %.100s.",
			    rhosts_files[rhosts_file_index]);
	  continue;
	}

      /* Check if authentication is permitted by the file. */
      if (check_rhosts_file(pw->pw_uid, buf, hostname, ipaddr, client_user, 
			    pw->pw_name))
	{
	  packet_send_debug("Accepted by %.100s.",
			    rhosts_files[rhosts_file_index]);
	  return 1;
	}
    }

  /* Rhosts authentication denied. */
  packet_send_debug("Rhosts/hosts.equiv authentication refused: client user '%.100s', server user '%.100s', client host '%.200s'.",
		    client_user, pw->pw_name, get_canonical_hostname());

  return 0;
}
