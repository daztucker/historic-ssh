/*

auth-rh-rsa.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@ssh.fi>, Espoo, Finland
Copyright (c) 1995-1999 SSH Communications Security Oy, Espoo, Finland
                        All rights reserved

Created: Sun May  7 03:08:06 1995 ylo

Rhosts or /etc/hosts.equiv authentication combined with RSA host
authentication.

*/

/*
 * $Id: auth-rh-rsa.c,v 1.4 1999/11/17 17:04:38 tri Exp $
 * $Log: auth-rh-rsa.c,v $
 * Revision 1.4  1999/11/17 17:04:38  tri
 * 	Fixed copyright notices.
 *
 * Revision 1.3  1998/03/27 16:53:36  kivinen
 *      Added ignore_root_rhosts support.
 *
 * Revision 1.2  1996/10/29 22:34:10  kivinen
 *      log -> log_msg.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 *      Imported ssh-1.2.13.
 *
 * Revision 1.5  1995/09/21  17:06:50  ylo
 *      Added ignore_rhosts.
 *
 * Revision 1.4  1995/08/31  09:18:58  ylo
 *      Tilde-expand the name of user hostfile.
 *
 * Revision 1.3  1995/07/13  01:12:51  ylo
 *      Removed the "Last modified" header.
 *
 * $Endlog$
 */

#include "includes.h"
#include "packet.h"
#include "ssh.h"
#include "xmalloc.h"

/* Tries to authenticate the user using the .rhosts file and the host using
   its host key.  Returns true if authentication succeeds. 
   .rhosts and .shosts will be ignored if ignore_rhosts is non-zero,
   unless the user is root and ignore_root_rhosts is zero. */

int auth_rhosts_rsa(RandomState *state,
                    struct passwd *pw, const char *client_user,
                    unsigned int client_host_key_bits,
                    MP_INT *client_host_key_e, MP_INT *client_host_key_n,
                    int ignore_rhosts, int ignore_root_rhosts,
                    int strict_modes)
{
  char *user_hostfile;
  const char *canonical_hostname;

  debug("Trying rhosts with RSA host authentication for %.100s", client_user);

  /* Check if we would accept it using rhosts authentication. */
  if (!auth_rhosts(pw, client_user, ignore_rhosts, ignore_root_rhosts,
                   strict_modes))
    return 0;

  canonical_hostname = get_canonical_hostname();

  debug("Rhosts RSA authentication: canonical host %.900s",
        canonical_hostname);
  
  /* Format the name of the file containing per-user known hosts. */
  user_hostfile = tilde_expand_filename(SSH_USER_HOSTFILE, pw->pw_uid);

  /* Check if we know the host and its host key. */
  /* Check system-wide host file. */
  if (check_host_in_hostfile(pw->pw_uid, SSH_SYSTEM_HOSTFILE, 
                             canonical_hostname,
                             client_host_key_bits, client_host_key_e,
                             client_host_key_n) != HOST_OK)
    {
      /* Check per-user host file.  Use the user's privileges. */
      if (check_host_in_hostfile(pw->pw_uid, user_hostfile, canonical_hostname,
                                 client_host_key_bits, client_host_key_e,
                                 client_host_key_n) != HOST_OK)
        {
          /* The host key was not found. */
          debug("Rhosts with RSA host authentication denied: unknown or invalid host key");
          packet_send_debug("Your host key cannot be verified: unknown or invalid host key.");
          packet_send_debug("The host name used to check the key was '%.200s'.",
                            get_canonical_hostname());
          packet_send_debug("Try logging back from the server machine with the canonical host name using ssh, and then try again.");
          return 0;
        }
      /* The host key was found. */
    }
  /* A matching host key was found and is known. */
  
  /* Perform the challenge-response dialog with the client for the host key. */
  if (!auth_rsa_challenge_dialog(state, client_host_key_bits,
                                 client_host_key_e, client_host_key_n))
    {
      log_msg("Client on %.800s failed to respond correctly to host authentication.",
          canonical_hostname);
      return 0;
    }

  /* We have authenticated the user using .rhosts or /etc/hosts.equiv, and
     the host using RSA.  We accept the authentication. */
  
  log_msg("Rhosts with RSA host authentication accepted for %.100s, %.100s on %.700s.",
      pw->pw_name, client_user, canonical_hostname);
  packet_send_debug("Rhosts with RSA host authentication accepted.");
  return 1;
}
