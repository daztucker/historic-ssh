/*

ssh-add.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Thu Apr  6 00:52:24 1995 ylo
Last modified: Wed Jul 12 01:50:45 1995 ylo

Adds an identity to the authentication server.

*/

#include "includes.h"
#include "randoms.h"
#include "rsa.h"
#include "ssh.h"
#include "xmalloc.h"
#include "authfd.h"

void delete_file(const char *filename)
{
  RSAPublicKey key;
  char *comment;
  AuthenticationConnection *ac;

  if (!load_public_key(filename, &key, &comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      return;
    }

  /* Send the request to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      rsa_clear_public_key(&key);
      xfree(comment);
      return;
    }
  if (ssh_remove_identity(ac, &key))
    fprintf(stderr, "Identity removed: %s (%s)\n", filename, comment);
  else
    fprintf(stderr, "Could not remove identity: %s\n", filename);
  rsa_clear_public_key(&key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void add_file(const char *filename)
{
  RSAPrivateKey key;
  RSAPublicKey public_key;
  AuthenticationConnection *ac;
  char *saved_comment, *comment;
  
  if (!load_public_key(filename, &public_key, &saved_comment))
    {
      printf("Bad key file %s: %s\n", filename, strerror(errno));
      return;
    }
  
  if (!load_private_key(filename, "", &key, &comment))
    {
      char buf[1024];
      char *pass;
      FILE *f;
      
      printf("Need passphrase for %s (%s).\n", filename, saved_comment);
      if (getenv("DISPLAY") && !isatty(fileno(stdin)))
	{
	  printf("Executing ssh-askpass to query the password...\n");
	  fflush(stdout);
	  fflush(stderr);
	  f = popen("ssh-askpass", "r");
	  if (!fgets(buf, sizeof(buf), f))
	    {
	      pclose(f);
	      xfree(saved_comment);
	      return;
	    }
	  pclose(f);
	  if (strchr(buf, '\n'))
	    *strchr(buf, '\n') = 0;
	  pass = xstrdup(buf);
	}
      else
	{
	  sprintf(buf, "Enter passphrase: ");
	  pass = read_passphrase(buf, 1);
	}
	  
      if (!load_private_key(filename, pass, &key, &comment))
	{
	  memset(pass, 0, strlen(pass));
	  fprintf(stderr, 
		  "Bad passphrase, file not readable, or invalid keyfile.\n");
	  xfree(saved_comment);
	  exit(1);
	}
      memset(pass, 0, strlen(pass));
    }

  xfree(saved_comment);

  /* Send the key to the authentication agent. */
  ac = ssh_get_authentication_connection();
  if (!ac)
    {
      fprintf(stderr,
	      "Could not open a connection to your authentication agent.\n");
      rsa_clear_private_key(&key);
      xfree(comment);
      return;
    }
  if (ssh_add_identity(ac, &key, comment))
    fprintf(stderr, "Identity added: %s (%s)\n", filename, comment);
  else
    fprintf(stderr, "Could not add identity: %s\n", filename);
  rsa_clear_private_key(&key);
  xfree(comment);
  ssh_close_authentication_connection(ac);
}

void list_identities()
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

  for (i = 1; i < ac; i++)
    {
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
	  exit(1);
	}
      sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);
      if (deleting)
	delete_file(buf);
      else
	add_file(buf);
    }
  exit(0);
}

void fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}
