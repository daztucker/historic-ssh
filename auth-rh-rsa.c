/*

auth-rh-rsa.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun May  7 03:08:06 1995 ylo
Last modified: Sun Jul  2 19:57:23 1995 ylo

Rhosts or /etc/hosts.equiv authentication combined with RSA host authentication.

*/

#include "includes.h"
#include "packet.h"
#include "ssh.h"
#include "xmalloc.h"

/* Tries to authenticate the user using the .rhosts file and the host using
   its host key.  Returns true if authentication succeeds. */

int auth_rhosts_rsa(RandomState *state,
		    struct passwd *pw, const char *client_user,
		    unsigned int client_host_key_bits,
		    MP_INT *client_host_key_e, MP_INT *client_host_key_n)
{
  char buf[1024];
  const char *canonical_hostname;

  debug("Trying rhosts with RSA host authentication for %.100s", client_user);

  /* Check if we would accept it using rhosts authentication. */
  if (!auth_rhosts(pw, client_user))
    return 0;

  canonical_hostname = get_canonical_hostname();

  debug("Rhosts RSA authentication: canonical host %.900s",
	canonical_hostname);
  
  /* Format the name of the file containing per-user known hosts. */
  sprintf(buf, "%s/%s", pw->pw_dir, SSH_USER_HOSTFILE);

  /* Check if we know the host and its host key. */
  if (check_host_in_hostfile(SSH_SYSTEM_HOSTFILE, canonical_hostname,
			     client_host_key_bits, client_host_key_e,
			     client_host_key_n) != HOST_OK &&
      check_host_in_hostfile(buf, canonical_hostname,
			     client_host_key_bits, client_host_key_e,
			     client_host_key_n) != HOST_OK)
    {
      debug("Rhosts with RSA host authentication denied: unknown or invalid host key");
      packet_send_debug("Your host key cannot be verified: unknown or invalid host key.");
      packet_send_debug("Try logging back from the server machine using ssh, and then try again.");
      return 0;
    }
  
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
