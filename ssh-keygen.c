/*

ssh-keygen.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1994 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 27 02:26:40 1995 ylo

Identity and host key generation and maintenance.

*/

/*
 * $Id: ssh-keygen.c,v 1.3 1995/07/26 17:11:31 ylo Exp $
 * $Log: ssh-keygen.c,v $
 * Revision 1.3  1995/07/26  17:11:31  ylo
 * 	Print version number in the usage string.
 *
 * Revision 1.2  1995/07/13  01:39:53  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#ifndef HAVE_GETHOSTNAME
#include <sys/utsname.h>
#endif
#include "randoms.h"
#include "rsa.h"
#include "ssh.h"
#include "xmalloc.h"

/* Generated private key. */
RSAPrivateKey private_key;

/* Generated public key. */
RSAPublicKey public_key;

/* Random number generator state. */
RandomState state;

/* Number of bits in the RSA key.  This value can be changed on the command
   line. */
int bits = 1024;

/* Flag indicating that we just want to change the passphrase.  This can be
   set on the command line. */
int change_passphrase = 0;

/* Flag indicating that we just want to change the comment.  This can be set
   on the command line. */
int change_comment = 0;

/* Perform changing a passphrase.  The argument is the passwd structure
   for the current user. */

void do_change_passphrase(struct passwd *pw)
{
  char buf[1024], *comment;
  RSAPrivateKey private_key;
  char *old_passphrase, *passphrase1, *passphrase2;
  struct stat st;

  /* Read key file name. */
  printf("Enter file in which the key is ($HOME/%s): ", SSH_CLIENT_IDENTITY);
  fflush(stdout);
  if (fgets(buf, sizeof(buf), stdin) == NULL)
    exit(1);
  if (strchr(buf, '\n'))
    *strchr(buf, '\n') = 0;
  if (strcmp(buf, "") == 0)
    sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);

  /* Check if the file exists. */
  if (stat(buf, &st) < 0)
    {
      perror(buf);
      exit(1);
    }
  
  /* Try to load the public key from the file the verify that it is
     readable and of the proper format. */
  if (!load_public_key(buf, &public_key, NULL))
    {
      printf("%s is not a valid key file.\n", buf);
      exit(1);
    }
  /* Clear the public key since we are just about to load the whole file. */
  rsa_clear_public_key(&public_key);

  /* Try to load the file with empty passphrase. */
  if (!load_private_key(buf, "", &private_key, &comment))
    {
      /* Read passphrase from the user. */
      old_passphrase = read_passphrase("Enter old passphrase: ", 1);
      /* Try to load using the passphrase. */
      if (!load_private_key(buf, old_passphrase, &private_key, &comment))
	{
	  memset(old_passphrase, 0, strlen(old_passphrase));
	  xfree(old_passphrase);
	  printf("Bad passphrase.\n");
	  exit(1);
	}
      /* Destroy the passphrase. */
      memset(old_passphrase, 0, strlen(old_passphrase));
      xfree(old_passphrase);
    }
  printf("Key has comment '%s'\n", comment);
  
  /* Ask the new passphrase (twice). */
  passphrase1 = 
    read_passphrase("Enter new passphrase (empty for no passphrase): ", 1);
  passphrase2 = read_passphrase("Enter same passphrase again: ", 1);

  /* Verify that they are the same. */
  if (strcmp(passphrase1, passphrase2) != 0)
    {
      memset(passphrase1, 0, strlen(passphrase1));
      memset(passphrase2, 0, strlen(passphrase2));
      xfree(passphrase1);
      xfree(passphrase2);
      printf("Pass phrases do not match.  Try again.\n");
      exit(1);
    }
  /* Destroy the other copy. */
  memset(passphrase2, 0, strlen(passphrase2));
  xfree(passphrase2);

  /* Save the file using the new passphrase. */
  if (!save_private_key(buf, passphrase1, &private_key, comment, &state))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase1, 0, strlen(passphrase1));
      xfree(passphrase1);
      rsa_clear_private_key(&private_key);
      xfree(comment);
      exit(1);
    }
  /* Destroy the passphrase and the copy of the key in memory. */
  memset(passphrase1, 0, strlen(passphrase1));
  xfree(passphrase1);
  rsa_clear_private_key(&private_key);
  xfree(comment);

  printf("Your identification has been saved with the new passphrase.\n");
  exit(0);
}

/* Change the comment of a private key file. */

void do_change_comment(struct passwd *pw)
{
  char buf[1024], new_comment[1024], *comment;
  RSAPrivateKey private_key;
  char *passphrase;
  struct stat st;
  FILE *f;

  /* Read key file name. */
  printf("Enter file in which the key is ($HOME/%s): ", SSH_CLIENT_IDENTITY);
  fflush(stdout);
  if (fgets(buf, sizeof(buf), stdin) == NULL)
    exit(1);
  if (strchr(buf, '\n'))
    *strchr(buf, '\n') = 0;
  if (strcmp(buf, "") == 0)
    sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);

  /* Check if the file exists. */
  if (stat(buf, &st) < 0)
    {
      perror(buf);
      exit(1);
    }
  
  /* Try to load the public key from the file the verify that it is
     readable and of the proper format. */
  if (!load_public_key(buf, &public_key, NULL))
    {
      printf("%s is not a valid key file.\n", buf);
      exit(1);
    }

  /* Try to load the file with empty passphrase. */
  if (load_private_key(buf, "", &private_key, &comment))
    passphrase = xstrdup("");
  else
    {
      /* Read passphrase from the user. */
      passphrase = read_passphrase("Enter passphrase: ", 1);
      /* Try to load using the passphrase. */
      if (!load_private_key(buf, passphrase, &private_key, &comment))
	{
	  memset(passphrase, 0, strlen(passphrase));
	  xfree(passphrase);
	  printf("Bad passphrase.\n");
	  exit(1);
	}
    }
  printf("Key now has comment '%s'\n", comment);

  printf("Enter new comment: ");
  fflush(stdout);
  if (!fgets(new_comment, sizeof(new_comment), stdin))
    {
      memset(passphrase, 0, strlen(passphrase));
      rsa_clear_private_key(&private_key);
      exit(1);
    }
  
  /* Remove terminating newline from comment. */
  if (strchr(new_comment, '\n'))
    *strchr(new_comment, '\n') = 0;

  /* Save the file using the new passphrase. */
  if (!save_private_key(buf, passphrase, &private_key, new_comment, &state))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase, 0, strlen(passphrase));
      xfree(passphrase);
      rsa_clear_private_key(&private_key);
      xfree(comment);
      exit(1);
    }

  /* Destroy the passphrase and the private key in memory. */
  memset(passphrase, 0, strlen(passphrase));
  xfree(passphrase);
  rsa_clear_private_key(&private_key);

  /* Save the public key in text format in a file with the same name but
     .pub appended. */
  strcat(buf, ".pub");
  f = fopen(buf, "w");
  if (!f)
    {
      printf("Could not save your public key in %s\n", buf);
      exit(1);
    }
  fprintf(f, "%d ", public_key.bits);
  mpz_out_str(f, 10, &public_key.e);
  fprintf(f, " ");
  mpz_out_str(f, 10, &public_key.n);
  fprintf(f, " %s\n", new_comment);
  fclose(f);

  xfree(comment);

  printf("The comment in your key file has been changed.\n");
  exit(0);
}

/* Main program for key management. */

int main(int ac, char **av)
{
  char buf[16384], buf2[1024], *passphrase1, *passphrase2;
  struct passwd *pw;
  int opt;
  struct stat st;
  FILE *f;
#ifdef HAVE_GETHOSTNAME
  char hostname[257];
#else
  struct utsname uts;
#endif
  extern int optind;
  extern char *optarg;

  /* Get user\'s passwd structure.  We need this for the home directory. */
  pw = getpwuid(getuid());
  if (!pw)
    {
      printf("You don't exist, go away!\n");
      exit(1);
    }

  /* Create ~/.ssh directory if it doesn\'t already exist. */
  sprintf(buf, "%s/%s", pw->pw_dir, SSH_USER_DIR);
  if (stat(buf, &st) < 0)
    if (mkdir(buf, 0755) < 0)
      error("Could not create directory '%s'.", buf);

  /* Parse command line arguments. */
  while ((opt = getopt(ac, av, "pcb:")) != EOF)
    {
      switch (opt)
	{
	case 'b':
	  bits = atoi(optarg);
	  if (bits < 512 || bits > 32768)
	    {
	      printf("Bits has bad value.\n");
	      exit(1);
	    }
	  break;

	case 'p':
	  change_passphrase = 1;
	  break;

	case 'c':
	  change_comment = 1;
	  break;

	case '?':
	default:
	  printf("ssh-keygen version %s\n", SSH_VERSION);
	  printf("Usage: %s [-b bits] [-p] [-c]\n", av[0]);
	  exit(1);
	}
    }
  if (optind < ac)
    {
      printf("Too many arguments.\n");
      exit(1);
    }
  if (change_passphrase && change_comment)
    {
      printf("Can only have one of -p and -c.\n");
      exit(1);
    }

  /* If the user requested to change the passphrase, do it now.  This
     function never returns. */
  if (change_passphrase)
    do_change_passphrase(pw);

  /* If the user requested to change the comment, do it now.  This function
     never returns. */
  if (change_comment)
    do_change_comment(pw);

  /* Initialize random number generator.  This may take a while if the
     user has no seed file, so display a message to the user. */
  printf("Initializing random number generator...\n");
  sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_SEEDFILE);
  random_initialize(&state, buf);

  /* Save random seed so we don\'t need to do all that time-consuming
     environmental noise collection the next time. */
  random_save(&state, buf);

  /* Generate the rsa key pair. */
  rsa_generate_key(&private_key, &public_key, &state, bits);

  /* Save the state again, just to remove any fear that the previous state
     could be used to recreate the key.  (That should not be possible anyway
     since the pool is stirred after save and some noise is added.) */
  random_save(&state, buf);

 ask_file_again:

  /* Ask for a file to save the key in. */
  printf("Enter file in which to save the key ($HOME/%s): ", 
	 SSH_CLIENT_IDENTITY);
  fflush(stdout);
  if (fgets(buf, sizeof(buf), stdin) == NULL)
    exit(1);
  if (strchr(buf, '\n'))
    *strchr(buf, '\n') = 0;
  if (strcmp(buf, "") == 0)
    sprintf(buf, "%s/%s", pw->pw_dir, SSH_CLIENT_IDENTITY);

  /* If the file aready exists, ask the user to confirm. */
  if (stat(buf, &st) >= 0)
    {
      printf("%s already exists.\n", buf);
      printf("Overwrite (y/n)? ");
      fflush(stdout);
      if (fgets(buf2, sizeof(buf2), stdin) == NULL)
	exit(1);
      if (buf2[0] != 'y' && buf2[0] != 'Y')
	exit(1);
    }
  
 passphrase_again:
  /* Ask for a passphrase (twice). */
  passphrase1 = 
    read_passphrase("Enter passphrase (empty for no passphrase): ", 1);
  passphrase2 = read_passphrase("Enter same passphrase again: ", 1);
  if (strcmp(passphrase1, passphrase2) != 0)
    {
      /* The passphrases do not match.  Clear them and retry. */
      memset(passphrase1, 0, strlen(passphrase1));
      memset(passphrase2, 0, strlen(passphrase2));
      xfree(passphrase1);
      xfree(passphrase2);
      printf("Passphrases do not match.  Try again.\n");
      goto passphrase_again;
    }
  /* Clear the other copy of the passphrase. */
  memset(passphrase2, 0, strlen(passphrase2));
  xfree(passphrase2);

  /* Create default commend field for the passphrase.  The user can later
     edit this field. */
#ifdef HAVE_GETHOSTNAME
  if (gethostname(hostname, sizeof(hostname)) < 0)
    {
      perror("gethostname");
      exit(1);
    }
  sprintf(buf2, "%s@%s", pw->pw_name, hostname);
#else
  if (uname(&uts) < 0)
    {
      perror("uname");
      exit(1);
    }
  sprintf(buf2, "%s@%s", pw->pw_name, uts.nodename);
#endif

  /* Save the key with the given passphrase and comment. */
  if (!save_private_key(buf, passphrase1, &private_key, buf2, &state))
    {
      printf("Saving the key failed: %s: %s.\n",
	     buf, strerror(errno));
      memset(passphrase1, 0, strlen(passphrase1));
      xfree(passphrase1);
      goto ask_file_again;
    }
  /* Clear the passphrase. */
  memset(passphrase1, 0, strlen(passphrase1));
  xfree(passphrase1);

  /* Clear the private key and the random number generator. */
  rsa_clear_private_key(&private_key);
  random_clear(&state);

  printf("Your identification has been saved in %s.\n", buf);

  /* Display the public key on the screen. */
  printf("Your public key is:\n");
  printf("%d ", public_key.bits);
  mpz_out_str(stdout, 10, &public_key.e);
  printf(" ");
  mpz_out_str(stdout, 10, &public_key.n);
  printf(" %s\n", buf2);

  /* Save the public key in text format in a file with the same name but
     .pub appended. */
  strcat(buf, ".pub");
  f = fopen(buf, "w");
  if (!f)
    {
      printf("Could not save your public key in %s\n", buf);
      exit(1);
    }
  fprintf(f, "%d ", public_key.bits);
  mpz_out_str(f, 10, &public_key.e);
  fprintf(f, " ");
  mpz_out_str(f, 10, &public_key.n);
  fprintf(f, " %s\n", buf2);
  fclose(f);

  printf("Your public key has been saved in %s\n", buf);
  
  exit(0);
}

/* May need to restore terminal modes and non-blocking status.  This should
   really be in log-client.c, but ssh.c wants to redefine this, and so must
   we too. */

void fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}
