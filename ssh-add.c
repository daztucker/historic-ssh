/*

ssh-add.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Thu Apr  6 00:52:24 1995 ylo

Adds an identity to the authentication server, or removes an identity.

*/

/*
 * $Id: ssh-add.c,v 1.6 1998/05/23 20:24:29 kivinen Exp $
 * $Log: ssh-add.c,v $
 * Revision 1.6  1998/05/23  20:24:29  kivinen
 * 	Changed () -> (void).
 *
 * Revision 1.5  1997/04/17  04:18:19  kivinen
 * 	Added -p (pipe) option support.
 *
 * Revision 1.4  1997/04/05 21:54:21  kivinen
 * 	Added check that userfile_get_des_1_magic_phrase succeeds.
 *
 * Revision 1.3  1997/03/19 17:37:59  kivinen
 * 	Added SECURE_RPC, SECURE_NFS and NIS_PLUS support from Andy
 * 	Polyakov <appro@fy.chalmers.se>.
 *
 * Revision 1.2  1996/10/20 16:19:33  ttsalo
 *      Added global variable 'original_real_uid' and it's initialization
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.4  1995/10/02  01:27:34  ylo
 * 	Loop asking for a proper passphrase until the user aborts or
 * 	gives an empty passphrase.  (This avoids problems of
 * 	accidentally typing the wrong passphrase without noticing it
 * 	when using ssh-add from .Xsession.real.)
 *
 * Revision 1.3  1995/08/29  22:24:21  ylo
 * 	Added delete_all.
 *
 * Revision 1.2  1995/07/13  01:38:15  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "randoms.h"
#include "rsa.h"
#include "ssh.h"
#include "xmalloc.h"
#include "authfd.h"

#define EXIT_STATUS_OK		0
#define EXIT_STATUS_NOAGENT	1
#define EXIT_STATUS_BADPASS	2
#define EXIT_STATUS_NOFILE	3
#define EXIT_STATUS_NOIDENTITY	4
#define EXIT_STATUS_ERROR	5

int exit_status = 0;

int use_stdin = 0;

uid_t original_real_uid;

void delete_file(const char *filename)
{
  RSAPublicKey key;
  char *comment;
  AuthenticationConnection *ac;

  if (!load_public_key(geteuid(), filename, &key, &comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      exit_status = EXIT_STATUS_NOFILE;
      return;
    }

  /* Send the request to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      exit_status = EXIT_STATUS_NOAGENT;
      rsa_clear_public_key(&key);
      xfree(comment);
      return;
    }
  if (ssh_remove_identity(ac, &key))
    fprintf(stderr, "Identity removed: %s (%s)\n", filename, comment);
  else
    {
      fprintf(stderr, "Could not remove identity: %s\n", filename);
      exit_status = EXIT_STATUS_NOIDENTITY;
    }
  rsa_clear_public_key(&key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void delete_all(void)
{
  AuthenticationConnection *ac;
  
  /* Get a connection to the agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      exit_status = EXIT_STATUS_NOAGENT;
      return;
    }

  /* Send a request to remove all identities. */
  if (ssh_remove_all_identities(ac))
    fprintf(stderr, "All identities removed.\n");
  else
    {
      fprintf(stderr, "Failed to remove all identitities.\n");
      exit_status = EXIT_STATUS_ERROR;
    }
  
  /* Close the connection to the agent. */
  ssh_close_authentication_connection(ac);
}

void add_file(const char *filename)
{
  RSAPrivateKey key;
  RSAPublicKey public_key;
  AuthenticationConnection *ac;
  char *saved_comment, *comment, *pass;
  int query_cnt;
  
  if (!load_public_key(geteuid(), filename, &public_key, &saved_comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      exit_status = EXIT_STATUS_NOFILE;
      return;
    }
  rsa_clear_public_key(&public_key);
  
  pass = xstrdup("");
  query_cnt = 0;
  while (!load_private_key(geteuid(), filename, pass, &key, &comment))
    {
      char buf[1024];
      FILE *f;
      
      /* Free the old passphrase. */
      memset(pass, 0, strlen(pass));
      xfree(pass);

#ifdef SECURE_RPC
      if (query_cnt == 0)
	{
	  pass = userfile_get_des_1_magic_phrase(geteuid());
	  if (pass == NULL)
	    pass = xstrdup("");
	  query_cnt = 1;
	  continue;
	}
#else
      if (query_cnt == 0)
	query_cnt = 1;
#endif
      
      
      /* Ask for a passphrase. */
      if (!use_stdin && getenv("DISPLAY") && !isatty(fileno(stdin)))
	{
	  sprintf(buf, "ssh-askpass '%sEnter passphrase for %.100s'", 
		  query_cnt <= 1 ? "" : "You entered wrong passphrase.  ", 
		  saved_comment);
	  f = popen(buf, "r");
	  if (!fgets(buf, sizeof(buf), f))
	    {
	      pclose(f);
	      xfree(saved_comment);
	      exit_status = EXIT_STATUS_BADPASS;
	      return;
	    }
	  pclose(f);
	  if (strchr(buf, '\n'))
	    *strchr(buf, '\n') = 0;
	  pass = xstrdup(buf);
	}
      else
	{
	  if (query_cnt <= 1)
	    printf("Need passphrase for %s (%s).\n", filename, saved_comment);
	  else
	    printf("Bad passphrase.\n");
	  pass = read_passphrase(geteuid(), "Enter passphrase: ", 1);
	  if (strcmp(pass, "") == 0)
	    {
	      xfree(saved_comment);
	      xfree(pass);
	      exit_status = EXIT_STATUS_BADPASS;
	      return;
	    }
	}
      query_cnt++;
    }
  memset(pass, 0, strlen(pass));
  xfree(pass);

  xfree(saved_comment);

  /* Send the key to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      exit_status = EXIT_STATUS_NOAGENT;
      rsa_clear_private_key(&key);
      xfree(comment);
      return;
    }
  if (ssh_add_identity(ac, &key, comment))
    fprintf(stderr, "Identity added: %s (%s)\n", filename, comment);
  else
    {
      fprintf(stderr, "Could not add identity: %s\n", filename);
      exit_status = EXIT_STATUS_ERROR;
    }
  rsa_clear_private_key(&key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void list_identities(void)
{
  AuthenticationConnection *ac;
  MP_INT e, n;
  int bits, status;
  char *comment;
  int had_identities;

  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr, "Could not connect to authentication server.\n");
      exit_status = EXIT_STATUS_NOAGENT;
      return;
    }
  mpz_init(&e);
  mpz_init(&n);
  had_identities = 0;
  for (status = ssh_get_first_identity(ac, &bits, &e, &n, &comment);
       status;
       status = ssh_get_next_identity(ac, &bits, &e, &n, &comment))
    {
      had_identities = 1;
      printf("%d ", bits);
      mpz_out_str(stdout, 10, &e);
      printf(" ");
      mpz_out_str(stdout, 10, &n);
      printf(" %s\n", comment);
      xfree(comment);
    }
  mpz_clear(&e);
  mpz_clear(&n);
  if (!had_identities)
    printf("The agent has no identities.\n");
  ssh_close_authentication_connection(ac);
}

int main(int ac, char **av)
{
  struct passwd *pw;
  char buf[1024];
  int no_files = 1;
  int i;
  int deleting = 0;
  
  original_real_uid = getuid();

  for (i = 1; i < ac; i++)
    {
      if (strcmp(av[i], "-p") == 0)
	{
	  use_stdin = 1;
	  continue;
	}
      if (strcmp(av[i], "-l") == 0)
	{
	  list_identities();
	  no_files = 0; /* Don't default-add/delete if -l. */
	  continue;
	}
      if (strcmp(av[i], "-d") == 0)
	{
	  deleting = 1;
	  continue;
	}
      if (strcmp(av[i], "-D") == 0)
	{
	  delete_all();
	  no_files = 0;
	  continue;
	}
      no_files = 0;
      if (deleting)
	delete_file(av[i]);
      else
	add_file(av[i]);
    }
  if (no_files)
    {
      pw = getpwuid(getuid());
      if (!pw)
	{
	  fprintf(stderr, "No user found with uid %d\n", (int)getuid());
	  exit(EXIT_STATUS_ERROR);
	}
      sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
      if (deleting)
	delete_file(buf);
      else
	add_file(buf);
    }
  exit(exit_status);
}
