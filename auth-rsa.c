/*

auth-rsa.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 27 01:46:52 1995 ylo

RSA-based authentication.  This code determines whether to admit a login
based on RSA authentication.  This file also contains functions to check
validity of the host key.

*/

/*
 * $Id: auth-rsa.c,v 1.7 1995/09/09 21:26:38 ylo Exp $
 * $Log: auth-rsa.c,v $
 * Revision 1.7  1995/09/09  21:26:38  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.6  1995/08/29  22:18:40  ylo
 * 	Permit using ip addresses in RSA authentication "from" option.
 *
 * Revision 1.5  1995/08/22  14:05:28  ylo
 * 	Added uid-swapping.
 *
 * Revision 1.4  1995/07/26  23:30:49  ylo
 * 	Added code to support protocol version 1.1.  The md hash of
 * 	RSA response must now include the session id.  Compatibility
 * 	code still handles older versions.
 *
 * Revision 1.3  1995/07/13  01:13:35  ylo
 * 	Removed the "Last modified" header.
 *
 * $Endlog$
 */

#include "includes.h"
#include "rsa.h"
#include "randoms.h"
#include "packet.h"
#include "xmalloc.h"
#include "ssh.h"
#include "md5.h"
#include "mpaux.h"
#include "uidswap.h"

/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;
extern int no_agent_forwarding_flag;
extern int no_x11_forwarding_flag;
extern int no_pty_flag;
extern char *forced_command;

/* Session identifier that is used to bind key exchange and authentication
   responses to a particular session. */
extern unsigned char session_id[16];

/* This is a compatibility kludge. */
extern int remote_protocol_1_1;

/* The .ssh/authorized_keys file contains public keys, one per line, in the
   following format:
     options bits e n comment
   where bits, e and n are decimal numbers, 
   and comment is any string of characters up to newline.  The maximum
   length of a line is 8000 characters.  See the documentation for a
   description of the options.
*/

/* Performs the RSA authentication challenge-response dialog with the client,
   and returns true (non-zero) if the client gave the correct answer to
   our challenge; returns zero if the client gives a wrong answer. */

int auth_rsa_challenge_dialog(RandomState *state, unsigned int bits,
			      MP_INT *e, MP_INT *n)
{
  MP_INT challenge, encrypted_challenge, aux;
  RSAPublicKey pk;
  unsigned char buf[32], mdbuf[16], response[16];
  struct MD5Context md;
  unsigned int i;

  mpz_init(&encrypted_challenge);
  mpz_init(&challenge);
  mpz_init(&aux);

  /* Generate a random challenge. */
  rsa_random_integer(&challenge, state, 256);
  mpz_mod(&challenge, &challenge, n);
  
  /* Create the public key data structure. */
  pk.bits = bits;
  mpz_init_set(&pk.e, e);
  mpz_init_set(&pk.n, n);

  /* Encrypt the challenge with the public key. */
  rsa_public_encrypt(&encrypted_challenge, &challenge, &pk, state);
  rsa_clear_public_key(&pk);

  /* Send the encrypted challenge to the client. */
  packet_start(SSH_SMSG_AUTH_RSA_CHALLENGE);
  packet_put_mp_int(&encrypted_challenge);
  packet_send();
  packet_write_wait();

  if (remote_protocol_1_1)
    { /* New protocol. */
      /* The response is MD5 of decrypted challenge plus session id. */
      mp_linearize_msb_first(buf, 32, &challenge);
      MD5Init(&md);
      MD5Update(&md, buf, 32);
      MD5Update(&md, session_id, 16);
      MD5Final(mdbuf, &md);
    }
  else
    { /* XXX remove this compatibility code later. */
      /* The client is supposed to respond with a 16-byte MD5 checksum of
	 the decrypted challenge converted to a 32 byte buffer by using
	 the least significant 8 bits for the first byte, etc.  We now compute
	 the correct response. */
      for (i = 0; i < 32; i++)
	{
	  mpz_mod_2exp(&aux, &challenge, 8);
	  buf[i] = mpz_get_ui(&aux);
	  mpz_div_2exp(&challenge, &challenge, 8);
	}

      MD5Init(&md);
      MD5Update(&md, buf, 32);
      MD5Final(mdbuf, &md);
    }

  /* We will no longer need these. */
  mpz_clear(&encrypted_challenge);
  mpz_clear(&challenge);
  mpz_clear(&aux);
  
  /* Wait for a response. */
  packet_read_expect(SSH_CMSG_AUTH_RSA_RESPONSE);
  for (i = 0; i < 16; i++)
    response[i] = packet_get_char();

  /* Verify that the response is the original challenge. */
  if (memcmp(response, mdbuf, 16) != 0)
    {
      /* Wrong answer. */
      return 0;
    }

  /* Correct answer. */
  return 1;
}

/* Performs the RSA authentication dialog with the client.  This returns
   0 if the client could not be authenticated, and 1 if authentication was
   successful.  This may exit if there is a serious protocol violation. */

int auth_rsa(struct passwd *pw, MP_INT *client_n, RandomState *state)
{
  char line[8192];
  int authenticated;
  unsigned int bits;
  MP_INT e, n;
  FILE *f;
  unsigned long linenum = 0;
  struct stat st;

  /* Open the file containing the authorized keys. */
  sprintf(line, "%.500s/%.100s", pw->pw_dir, SSH_USER_PERMITTED_KEYS);
  
  /* Temporarily use the user's uid. */
  temporarily_use_uid(pw->pw_uid);
  if (stat(line, &st) < 0)
    {
      /* Restore the privileged uid. */
      restore_uid();
      return 0;
    }
  f = fopen(line, "r");
  if (!f)
    {
      /* Restore the privileged uid. */
      restore_uid();
      packet_send_debug("Could not open %.900s for reading.", line);
      packet_send_debug("If your home is on an NFS volume, it may need to be world-readable.");
      return 0;
    }

  /* Flag indicating whether authentication has succeeded. */
  authenticated = 0;
  
  /* Initialize mp-int variables. */
  mpz_init(&e);
  mpz_init(&n);

  /* Go though the accepted keys, looking for the current key.  If found,
     perform a challenge-response dialog to verify that the user really has
     the corresponding private key. */
  while (fgets(line, sizeof(line), f))
    {
      char *cp;
      char *options;

      linenum++;

      /* Skip leading whitespace. */
      for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
	;

      /* Skip empty and comment lines. */
      if (!*cp || *cp == '\n' || *cp == '#')
	continue;

      /* Check if there are options for this key, and if so, save their 
	 starting address and skip the option part for now.  If there are no 
	 options, set the starting address to NULL. */
      if (*cp < '0' || *cp > '9')
	{
	  int quoted = 0;
	  options = cp;
	  for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++)
	    {
	      if (*cp == '\\' && cp[1] == '"')
		cp++; /* Skip both */
	      else
		if (*cp == '"')
		  quoted = !quoted;
	    }
	}
      else
	options = NULL;
      
      /* Parse the key from the line. */
      if (!auth_rsa_read_key(&cp, &bits, &e, &n))
	{
	  debug("%.100s, line %lu: bad key syntax", 
		SSH_USER_PERMITTED_KEYS, linenum);
	  packet_send_debug("%.100s, line %lu: bad key syntax", 
			    SSH_USER_PERMITTED_KEYS, linenum);
	  continue;
	}
      /* cp now points to the comment part. */

      /* Check if the we have found the desired key (identified by its
	 modulus). */
      if (mpz_cmp(&n, client_n) != 0)
	continue; /* Wrong key. */

      /* We have found the desired key. */

      /* Perform the challenge-response dialog for this key. */
      if (!auth_rsa_challenge_dialog(state, bits, &e, &n))
	{
	  /* Wrong response. */
	  log("Wrong response to RSA authentication challenge.");
	  packet_send_debug("Wrong response to RSA authentication challenge.");
	  continue;
	}

      /* Correct response.  The client has been successfully authenticated.
	 Note that we have not yet processed the options; this will be reset
	 if the options cause the authentication to be rejected. */
      authenticated = 1;

      /* RSA part of authentication was accepted.  Now process the options. */
      if (options)
	{
	  while (*options && *options != ' ' && *options != '\t')
	    {
	      cp = "no-port-forwarding";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  packet_send_debug("Port forwarding disabled.");
		  no_port_forwarding_flag = 1;
		  options += strlen(cp);
		  goto next_option;
		}
	      cp = "no-agent-forwarding";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  packet_send_debug("Agent forwarding disabled.");
		  no_agent_forwarding_flag = 1;
		  options += strlen(cp);
		  goto next_option;
		}
	      cp = "no-X11-forwarding";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  packet_send_debug("X11 forwarding disabled.");
		  no_x11_forwarding_flag = 1;
		  options += strlen(cp);
		  goto next_option;
		}
	      cp = "no-pty";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  packet_send_debug("Pty allocation disabled.");
		  no_pty_flag = 1;
		  options += strlen(cp);
		  goto next_option;
		}
	      cp = "command=\"";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  int i;
		  options += strlen(cp);
		  forced_command = xmalloc(strlen(options) + 1);
		  i = 0;
		  while (*options)
		    {
		      if (*options == '"')
			break;
		      if (*options == '\\' && options[1] == '"')
			{
			  options += 2;
			  forced_command[i++] = '"';
			  continue;
			}
		      forced_command[i++] = *options++;
		    }
		  if (!*options)
		    {
		      debug("%.100s, line %lu: missing end quote",
			    SSH_USER_PERMITTED_KEYS, linenum);
		      packet_send_debug("%.100s, line %lu: missing end quote",
					SSH_USER_PERMITTED_KEYS, linenum);
		      continue;
		    }
		  forced_command[i] = 0;
		  packet_send_debug("Forced command: %.900s", forced_command);
		  options++;
		  goto next_option;
		}
	      cp = "from=\"";
	      if (strncmp(options, cp, strlen(cp)) == 0)
		{
		  char *patterns = xmalloc(strlen(options) + 1);
		  int i;
		  options += strlen(cp);
		  i = 0;
		  while (*options)
		    {
		      if (*options == '"')
			break;
		      if (*options == '\\' && options[1] == '"')
			{
			  options += 2;
			  patterns[i++] = '"';
			  continue;
			}
		      patterns[i++] = *options++;
		    }
		  if (!*options)
		    {
		      debug("%.100s, line %lu: missing end quote",
			    SSH_USER_PERMITTED_KEYS, linenum);
		      packet_send_debug("%.100s, line %lu: missing end quote",
					SSH_USER_PERMITTED_KEYS, linenum);
		      continue;
		    }
		  patterns[i] = 0;
		  options++;
		  if (!match_hostname(get_canonical_hostname(), patterns,
				     strlen(patterns)) &&
		      !match_hostname(get_remote_ipaddr(), patterns,
				      strlen(patterns)))
		    {
		      log("RSA authentication tried for %.100s with correct key but not from a permitted host (host=%.200s, ip=%.200s).",
			  pw->pw_name, get_canonical_hostname(),
			  get_remote_ipaddr());
		      packet_send_debug("Your host '%.200s' is not permitted to use this key for login.",
					get_canonical_hostname());
		      xfree(patterns);
		      authenticated = 0;
		      break;
		    }
		  xfree(patterns);
		  /* Host name matches. */
		  goto next_option;
		}
	    bad_option:
	      /* Unknown option. */
	      log("Bad options in %.100s file, line %lu: %.50s",
		  SSH_USER_PERMITTED_KEYS, linenum, options);
	      packet_send_debug("Bad options in %.100s file, line %lu: %.50s",
				SSH_USER_PERMITTED_KEYS, linenum, options);
	      authenticated = 0;
	      break;

	    next_option:
	      /* Skip the comma, and move to the next option (or break out
		 if there are no more). */
	      if (!*options)
		fatal("Bugs in auth-rsa.c option processing.");
	      if (*options == ' ' || *options == '\t')
		break; /* End of options. */
	      if (*options != ',')
		goto bad_option;
	      options++;
	      /* Process the next option. */
	      continue;
	    }
	}

      /* Break out of the loop if authentication was successful; otherwise
	 continue searching. */
      if (authenticated)
	break;
    }

  /* Restore the privileged uid. */
  restore_uid();

  /* Close the file. */
  fclose(f);
  
  /* Clear any mp-int variables. */
  mpz_clear(&n);
  mpz_clear(&e);

  if (authenticated)
    packet_send_debug("RSA authentication accepted.");

  /* Return authentication result. */
  return authenticated;
}
