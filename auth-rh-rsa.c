/*

auth-rh-rsa.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun May  7 03:08:06 1995 ylo

Rhosts or /etc/hosts.equiv authentication combined with RSA host
authentication.

*/

#include "includes.h"
RCSID("$Id: auth-rh-rsa.c,v 1.6 1999/11/10 21:38:58 bg Exp $");

#include "packet.h"
#include "ssh.h"
#include "xmalloc.h"
#include "uidswap.h"

/*
 * If somebody can come up with a portable or atleast manageable way
 * of implementing file_is_local() please tell bg@sics.se.
 */
#if defined(__FreeBSD__) && (__FreeBSD__ >= 3)
#include <sys/param.h>
#include <sys/mount.h>
#define HAVE_FILE_IS_LOCAL
static int
file_is_local(const char *fnam)
{
  struct statfs st;
  if (statfs(fnam, &st) < 0)
    return 0;
  if (strcmp(st.f_fstypename, "ufs") == 0)
    return 1;

  return 0;
}
#endif /* __FreeBSD__ */

#if 0
/* This is known to work under some Linuxes */
#include <sys/vfs.h>
#define HAVE_FILE_IS_LOCAL
static int
file_is_local(const char *fnam)
{
  struct statfs st;
  if (statfs(fnam, &st) < 0)
    return 0;
  if (st.f_type == 0xEF53)	/* Ext2fs */
    return 1;
  if (st.f_type == 0xEF51)	/* Old Ext2fs */
    return 1;
  if (st.f_type == 0x137D)	/* Extfs */
    return 1;
  if (st.f_type == 0x00011954)	/* UFS */
    return 1;

  return 0;
}
#endif /* __FreeBSD__ */

/* Tries to authenticate the user using the .rhosts file and the host using
   its host key.  Returns true if authentication succeeds. 
   .rhosts and .shosts will be ignored if ignore_rhosts is non-zero. */

int auth_rhosts_rsa(RandomState *state,
		    struct passwd *pw, const char *client_user,
		    unsigned int client_host_key_bits,
		    BIGNUM *client_host_key_e, BIGNUM *client_host_key_n,
		    int ignore_rhosts, int strict_modes)
{
  const char *canonical_hostname;
  HostStatus host_status;

  debug("Trying rhosts with RSA host authentication for %.100s", client_user);

  /* Check if we would accept it using rhosts authentication. */
  if (!auth_rhosts(pw, client_user, ignore_rhosts, strict_modes))
    return 0;

  canonical_hostname = get_canonical_hostname();

  debug("Rhosts RSA authentication: canonical host %.900s",
	canonical_hostname);
  
  /* Check if we know the host and its host key. */
  /* Check system-wide host file. */
  host_status = check_host_in_hostfile(SSH_SYSTEM_HOSTFILE, canonical_hostname,
				       client_host_key_bits, client_host_key_e,
				       client_host_key_n);

#ifdef HAVE_FILE_IS_LOCAL
  /* Check per-user host file.  Use the user's privileges. */
  if (host_status != HOST_OK)
    {
      struct stat st;
      /* Format the name of the file containing per-user known hosts. */
      char *user_hostfile=tilde_expand_filename(SSH_USER_HOSTFILE, pw->pw_uid);

      temporarily_use_uid(pw->pw_uid);
      
      /* First check file permissions of SSH_USER_HOSTFILE, auth_rsa()
	 did already check pw->pw_dir, but there is a race XXX */
      if (!file_is_local(user_hostfile))
	{
	  log("Rhosts RSA authentication refused for %.100s: %.200s is not local", pw->pw_name, user_hostfile);
	    restore_uid();
	    return 0;
	}
      if (strict_modes)
	if (stat(user_hostfile, &st) < 0
	    || (st.st_uid != 0 && st.st_uid != pw->pw_uid)
	    || (st.st_mode & 022) != 0)
	  {
	    log("Rhosts RSA authentication refused for %.100s: bad owner or modes for %.200s", pw->pw_name, user_hostfile);
	    restore_uid();
	    return 0;
	  }
      host_status = check_host_in_hostfile(user_hostfile, canonical_hostname,
					   client_host_key_bits,
					   client_host_key_e,
					   client_host_key_n);
      /* Restore privileges. */
      restore_uid();
    }
#endif /* HAVE_FILE_IS_LOCAL */

  if (host_status != HOST_OK)
    {
      /* The host key was not found. */
      debug("Rhosts with RSA host authentication denied: unknown or invalid host key");
      packet_send_debug("Your host key cannot be verified: unknown or invalid host key.");
      return 0;
    }
  /* A matching host key was found and is known. */
  
  /* Perform the challenge-response dialog with the client for the host key. */
  if (!auth_rsa_challenge_dialog(state, client_host_key_bits,
				 client_host_key_e, client_host_key_n))
    {
      log("Client on %.800s failed to respond correctly to host authentication.",
	  canonical_hostname);
      return 0;
    }

  /* We have authenticated the user using .rhosts or /etc/hosts.equiv, and
     the host using RSA.  We accept the authentication. */
  
  log("Rhosts with RSA host authentication accepted for %.100s, %.100s on %.700s.",
      pw->pw_name, client_user, canonical_hostname);
  packet_send_debug("Rhosts with RSA host authentication accepted.");
  return 1;
}
