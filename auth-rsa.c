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
 * $Id: auth-rsa.c,v 1.12 1999/02/21 19:51:55 ylo Exp $
 * $Log: auth-rsa.c,v $
 * Revision 1.12  1999/02/21 19:51:55  ylo
 * 	Intermediate commit of ssh1.2.27 stuff.
 * 	Main change is sprintf -> snprintf; however, there are also
 * 	many other changes.
 *
 * Revision 1.11  1998/07/08 00:38:52  kivinen
 *      Added ip address to match_hostname function.
 *
 * Revision 1.10  1998/01/15  13:08:30  kivinen
 *      Fixed no-X11-forwarding to no-x11-forwarding.
 *
 * Revision 1.9  1998/01/03 06:39:47  kivinen
 *      Fixed bug in option_compare. Added code that will insert also
 *      the last allow/deny forwarding port/to to the table. Fixed
 *      count incrementation.
 *
 * Revision 1.8  1998/01/02 06:15:25  kivinen
 *      Changed option names to be case insensitive. Added
 *      {allow,deny}forwarding{port,to} options (commercial version only).
 *
 * Revision 1.7  1997/03/26 05:31:01  kivinen
 *      Added support for idle-timeout.
 *      Added better error message if .ssh directory is missing.
 *
 * Revision 1.6  1996/10/29 22:34:38  kivinen
 *      log -> log_msg.
 *
 * Revision 1.5  1996/10/11 13:01:56  ttsalo
 *      Fixed the checking of existence of authorized_keys.
 *
 * Revision 1.4  1996/10/04 12:51:26  ylo
 *      Fixed a bug in the last fix in RSA authentication.
 *
 * Revision 1.3  1996/10/04 00:51:36  ylo
 *      Check existence of authorized_keys BEFORE checking its
 *      permissions to avoid bogus warnings.
 *
 * Revision 1.2  1996/08/13 09:04:25  ttsalo
 *      Home directory, .ssh and .ssh/authorized_keys are now
 *      checked for wrong owner and group & world writeability.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 *      Imported ssh-1.2.13.
 *
 * Revision 1.8  1995/09/21  17:08:00  ylo
 *      Added uidswap.h.
 *
 * Revision 1.7  1995/09/09  21:26:38  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.6  1995/08/29  22:18:40  ylo
 *      Permit using ip addresses in RSA authentication "from" option.
 *
 * Revision 1.5  1995/08/22  14:05:28  ylo
 *      Added uid-swapping.
 *
 * Revision 1.4  1995/07/26  23:30:49  ylo
 *      Added code to support protocol version 1.1.  The md hash of
 *      RSA response must now include the session id.  Compatibility
 *      code still handles older versions.
 *
 * Revision 1.3  1995/07/13  01:13:35  ylo
 *      Removed the "Last modified" header.
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
#include "userfile.h"
#include "servconf.h"

/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;
extern int no_agent_forwarding_flag;
extern int no_x11_forwarding_flag;
extern int no_pty_flag;
extern time_t idle_timeout;
extern char *forced_command;
extern struct envstring *custom_environment;
extern ServerOptions options;

/* Session identifier that is used to bind key exchange and authentication
   responses to a particular session. */
extern unsigned char session_id[16];

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

  /* The response is MD5 of decrypted challenge plus session id. */
  mp_linearize_msb_first(buf, 32, &challenge);
  MD5Init(&md);
  MD5Update(&md, buf, 32);
  MD5Update(&md, session_id, 16);
  MD5Final(mdbuf, &md);

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

/* Compare option line to option name. Match only as many characters as there
   are in the option name, and make the match case insensitive. Return true if
   the names match, and false otherwise. */
int option_compare(const char *options_line, const char *option_name)
{
  char *tmp;
  int i, len, ret;
  
  len = strlen(option_name);
  
  if (strlen(options_line) < len)
    return 0;
  
  tmp = xmalloc(len + 1);
  for(i = 0; i < len; i++)
    tmp[i] = tolower(options_line[i]);
  tmp[i] = '\0';

  ret = strcmp(tmp, option_name);
  xfree(tmp);
  return (ret == 0);
}

/* Performs the RSA authentication dialog with the client.  This returns
   0 if the client could not be authenticated, and 1 if authentication was
   successful.  This may exit if there is a serious protocol violation. */

int auth_rsa(struct passwd *pw, MP_INT *client_n, RandomState *state,
             int strict_modes)
{
  char line[8192];
  int authenticated;
  unsigned int bits;
  MP_INT e, n;
  UserFile uf;
  unsigned long linenum = 0;
  struct stat st;

  /* Check permissions & owner of user's .ssh directory */
  snprintf(line, sizeof(line), "%.500s/%.100s", pw->pw_dir, SSH_USER_DIR);

  /* Check permissions & owner of user's home directory */
  if (strict_modes && !userfile_check_owner_permissions(pw, pw->pw_dir))
    {
      log_msg("Rsa authentication refused for %.100s: bad modes for %.200s",
          pw->pw_name, pw->pw_dir);
      packet_send_debug("Bad file modes for %.200s", pw->pw_dir);
      return 0;
    }

  /* Check if user have .ssh directory */
  if (userfile_stat(pw->pw_uid, line, &st) < 0)
    {
      log_msg("Rsa authentication refused for %.100s: no %.200s directory",
              pw->pw_name, line);
      packet_send_debug("Rsa authentication refused, no %.200s directory",
                        line);
      return 0;
    }
  
  if (strict_modes && !userfile_check_owner_permissions(pw, line))
    {
      log_msg("Rsa authentication refused for %.100s: bad modes for %.200s",
          pw->pw_name, line);
      packet_send_debug("Bad file modes for %.200s", line);
      return 0;
    }
  
  /* Check permissions & owner of user's authorized keys file */
  snprintf(line, sizeof(line),
           "%.500s/%.100s", pw->pw_dir, SSH_USER_PERMITTED_KEYS);

  /* Open the file containing the authorized keys. */
  if (userfile_stat(pw->pw_uid, line, &st) < 0)
    return 0;

  if (strict_modes && !userfile_check_owner_permissions(pw, line))
    {
      log_msg("Rsa authentication refused for %.100s: bad modes for %.200s",
          pw->pw_name, line);
      packet_send_debug("Bad file modes for %.200s", line);
      return 0;
    }

  uf = userfile_open(pw->pw_uid, line, O_RDONLY, 0);
  if (uf == NULL)
    {
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
  while (userfile_gets(line, sizeof(line), uf))
    {
      char *cp;
      char *opts;
#ifdef F_SECURE_COMMERCIAL

#endif /* F_SECURE_COMMERCIAL */

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
          opts = cp;
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
        opts = NULL;
      
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
          log_msg("Wrong response to RSA authentication challenge.");
          packet_send_debug("Wrong response to RSA authentication challenge.");
          continue;
        }

      /* Correct response.  The client has been successfully authenticated.
         Note that we have not yet processed the options; this will be reset
         if the options cause the authentication to be rejected. */
      authenticated = 1;

      /* RSA part of authentication was accepted.  Now process the options. */
      if (opts)
        {
          while (*opts && *opts != ' ' && *opts != '\t')
            {
              cp = "no-port-forwarding";
              if (option_compare(opts, cp))
                {
                  packet_send_debug("Port forwarding disabled.");
                  no_port_forwarding_flag = 1;
                  opts += strlen(cp);
                  goto next_option;
                }
              cp = "no-agent-forwarding";
              if (option_compare(opts, cp))
                {
                  packet_send_debug("Agent forwarding disabled.");
                  no_agent_forwarding_flag = 1;
                  opts += strlen(cp);
                  goto next_option;
                }
              cp = "no-x11-forwarding";
              if (option_compare(opts, cp))
                {
                  packet_send_debug("X11 forwarding disabled.");
                  no_x11_forwarding_flag = 1;
                  opts += strlen(cp);
                  goto next_option;
                }
              cp = "no-pty";
              if (option_compare(opts, cp))
                {
                  packet_send_debug("Pty allocation disabled.");
                  no_pty_flag = 1;
                  opts += strlen(cp);
                  goto next_option;
                }
              cp = "idle-timeout=";
              if (option_compare(opts, cp))
                {
                  int value;
                  opts += strlen(cp);
                  value = 0;
                  while(isdigit(*opts))
                    {
                      value *= 10;
                      value += *opts - '0';
                      opts++;
                    }
                  *opts = tolower(*opts);
                  if (*opts == 'w') /* Weeks */
                    {
                      value *= 7 * 24 * 60 * 60;
                      opts++;
                    }
                  else if (*opts == 'd') /* Days */
                    {
                      value *= 24 * 60 * 60;
                      opts++;
                    }
                  else if (*opts == 'h') /* Hours */
                    {
                      value *= 60 * 60;
                      opts++;
                    }
                  else if (*opts == 'm') /* Minutes */
                    {
                      value *= 60;
                      opts++;
                    }
                  else if (*opts == 's')
                    {
                      opts++;
                    }
                  packet_send_debug("Idle timeout set to %d seconds.",
                                    value);
                  idle_timeout = value;
                  goto next_option;
                }
#ifdef F_SECURE_COMMERCIAL

































































































































#endif /* F_SECURE_COMMERCIAL */
              cp = "command=\"";
              if (option_compare(opts, cp))
                {
                  int i;
                  opts += strlen(cp);
                  forced_command = xmalloc(strlen(opts) + 1);
                  i = 0;
                  while (*opts)
                    {
                      if (*opts == '"')
                        break;
                      if (*opts == '\\' && opts[1] == '"')
                        {
                          opts += 2;
                          forced_command[i++] = '"';
                          continue;
                        }
                      forced_command[i++] = *opts++;
                    }
                  if (!*opts)
                    {
                      debug("%.100s, line %lu: missing end quote",
                            SSH_USER_PERMITTED_KEYS, linenum);
                      packet_send_debug("%.100s, line %lu: missing end quote",
                                        SSH_USER_PERMITTED_KEYS, linenum);
                      continue;
                    }
                  forced_command[i] = 0;
                  packet_send_debug("Forced command: %.900s", forced_command);
                  opts++;
                  goto next_option;
                }
              cp = "environment=\"";
              if (option_compare(opts, cp))
                {
                  int i;
                  char *s;
                  struct envstring *new_envstring;
                  opts += strlen(cp);
                  s = xmalloc(strlen(opts) + 1);
                  i = 0;
                  while (*opts)
                    {
                      if (*opts == '"')
                        break;
                      if (*opts == '\\' && opts[1] == '"')
                        {
                          opts += 2;
                          s[i++] = '"';
                          continue;
                        }
                      s[i++] = *opts++;
                    }
                  if (!*opts)
                    {
                      debug("%.100s, line %lu: missing end quote",
                            SSH_USER_PERMITTED_KEYS, linenum);
                      packet_send_debug("%.100s, line %lu: missing end quote",
                                        SSH_USER_PERMITTED_KEYS, linenum);
                      continue;
                    }
                  s[i] = 0;
                  packet_send_debug("Adding to environment: %.900s", s);
                  debug("Adding to environment: %.900s", s);
                  opts++;
                  new_envstring = xmalloc(sizeof(struct envstring));
                  new_envstring->s = s;
                  new_envstring->next = custom_environment;
                  custom_environment = new_envstring;
                  goto next_option;
                }
              cp = "from=\"";
              if (option_compare(opts, cp))
                {
                  char *patterns = xmalloc(strlen(opts) + 1);
                  int i;
                  opts += strlen(cp);
                  i = 0;
                  while (*opts)
                    {
                      if (*opts == '"')
                        break;
                      if (*opts == '\\' && opts[1] == '"')
                        {
                          opts += 2;
                          patterns[i++] = '"';
                          continue;
                        }
                      patterns[i++] = *opts++;
                    }
                  if (!*opts)
                    {
                      debug("%.100s, line %lu: missing end quote",
                            SSH_USER_PERMITTED_KEYS, linenum);
                      packet_send_debug("%.100s, line %lu: missing end quote",
                                        SSH_USER_PERMITTED_KEYS, linenum);
                      continue;
                    }
                  patterns[i] = 0;
                  opts++;
                  if (!match_hostname(get_canonical_hostname(),
                                      get_remote_ipaddr(), patterns,
                                      strlen(patterns)))
                    {
                      log_msg("RSA authentication tried for %.100s with correct key but not from a permitted host (host=%.200s, ip=%.200s).",
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
              log_msg("Bad options in %.100s file, line %lu: %.50s",
                  SSH_USER_PERMITTED_KEYS, linenum, opts);
              packet_send_debug("Bad options in %.100s file, line %lu: %.50s",
                                SSH_USER_PERMITTED_KEYS, linenum, opts);
              authenticated = 0;
              break;

            next_option:
              /* Skip the comma, and move to the next option (or break out
                 if there are no more). */
              if (!*opts)
                fatal("Bugs in auth-rsa.c option processing.");
              if (*opts == ' ' || *opts == '\t')
                break; /* End of options. */
              if (*opts != ',')
                goto bad_option;
              opts++;
              /* Process the next option. */
              continue;
            }
        }

      /* Break out of the loop if authentication was successful; otherwise
         continue searching. */
      if (authenticated)
        break;
    }

  /* Close the file. */
  userfile_close(uf);
  
  /* Clear any mp-int variables. */
  mpz_clear(&n);
  mpz_clear(&e);

  if (authenticated)
    packet_send_debug("RSA authentication accepted.");

  /* Return authentication result. */
  return authenticated;
}
