/*

sshsia.c

Author: Tom Woodburn <woodburn@zk3.dec.com>

Helper functions for using the SIA (Security Integration Architecture)
functions of Tru64 UNIX.

ssh_sia_initialize() is based on initialize_osf_security() from Christophe
Wolfhugel's osfc2.c (Copyright (c) 1995 Christophe Wolfhugel). 

Copyright (c) 1999 COMPAQ Computer Corp, all rights reserved
Copyright (c) 1999 SSH Communications Security Oy, Espoo, Finland

*/

/*
 * $Id: sshsia.c,v 1.6 1999/11/17 15:54:48 tri Exp $
 * $Log: sshsia.c,v $
 * Revision 1.6  1999/11/17 15:54:48  tri
 * 	Streamlined local SIA interface names.
 *
 * Revision 1.5  1999/11/17 15:48:05  tri
 *      Fixed copyright notice.
 *
 * Revision 1.1  1999/04/29 07:52:32  tri
 *      Replaced OSF1/C2 security support with more complete SIA
 *         (Security Integration Architecture) support by Tom Woodburn.
 *
 * $Endlog$
 */

#include "includes.h"
#include "ssh.h"
#include "sshsia.h"
#include <prot.h>

static int argc = 0;
static char **argv = NULL;
static int c2security = 0;

void
ssh_sia_initialize(int ac, char **av)
{
  FILE *f;
  char buf[256];
  char siad[] = "siad_ses_init=";

  argc = ac;
  argv = av;

  if (access(SIAIGOODFILE, F_OK) == -1)
    {
      /* Broken OSF/1 system, better don't run on it. */
      fprintf(stderr, "%s does not exist. Your OSF/1 system is probably broken.\n",
              SIAIGOODFILE);
      exit(1);
    }
  if ((f = fopen(MATRIX_CONF, "r")) == NULL)
    {
      /* Another way OSF/1 is probably broken. */
      fprintf(stderr, "%s unreadable. Your OSF/1 system is probably broken.\n",
              MATRIX_CONF); 
      exit(1);
    }
  
  /* Read matrix.conf to check if we run C2 or not */
  while (fgets(buf, sizeof(buf), f) != NULL)
    {
      if (strncmp(buf, siad, sizeof(siad) - 1) == 0)
        {
          if (strstr(buf, "OSFC2") != NULL)
            c2security = 1;
          break;
        }
    }
  fclose(f);
  log_msg("OSF/1: security level : %.100s", c2security == 0 ? "not C2" : "C2");
  if (c2security == 1)
    set_auth_parameters(ac, av);
}

/* ssh_sia_get_args() returns the arguments passed to ssh_sia_initialize(), which
   typically are the arguments from main(). */

void
ssh_sia_get_args(int *ac, char ***av)
{
  *ac = argc;
  *av = argv;
}

/* The only reason we have our own version of sia_validate_user()
   is that we need to authenticate the user through sia_ses_authent().
   sia_validate_user() uses sia_ses_reauthent().

   We need sia_ses_authent() because it logs unsuccessful logins.
   sia_ses_reauthent() doesn't (at least not yet). */

/*
 * NAME:  ssh_sia_validate_user
 *
 * FUNCTION:  Verify a user/passphrase combination.
 *
 * RETURNS:
 *      SIASUCCESS on success,
 *      SIAFAIL on failure.
 *
 */

int
ssh_sia_validate_user(sia_collect_func_t *collect, /* communication routine */
                     int argc,
                     char **argv,
                     char *hostname,    /* remote host (or user@host) info */
                     char *username,
                     char *tty,         /* ttyname() or X display (if any) */
                     int colinput,      /* can call collect() for input */
                     char *gssapi,
                     char *passphrase)  /* pre-gathered passphrase (bad) */
{
  SIAENTITY *ent = NULL;
  int status;

  status = sia_ses_init(&ent, argc, argv,
                        hostname, username, tty, colinput, gssapi);
  if (status != SIASUCCESS || !ent)
    return SIAFAIL;

  status = sia_ses_authent(collect, passphrase, ent);
  (void) sia_ses_release(&ent);
  return status;
}

/* ssh_sia_no_password() returns 1 if the user has a null password and is
   allowed to login with it, 0 otherwise.

   sshd makes the same check on other platforms by calling:

        auth_password(server_user, "");

   It can't do that with SIA because the call to sia_verify_user() in
   auth_password() would have a side effect for users without null passwords
   (the typical case).  The side effect is that an "authentication failure"
   audit record would be generated. */

int
ssh_sia_no_password(const char *server_user)
{
  int no_password = 0;

  if (c2security == 1)
    {
      struct pr_passwd *pr = getprpwnam(server_user);
      if (pr)
        {
          int nullpwok = 0;
          if (pr->uflg.fg_nullpw)
            nullpwok = pr->ufld.fd_nullpw;
          else if (pr->sflg.fg_nullpw)
            nullpwok = pr->sfld.fd_nullpw;

          if (nullpwok &&
              !pr->uflg.fg_encrypt ||
              !pr->ufld.fd_encrypt || !pr->ufld.fd_encrypt[0])
            no_password = 1;
        }
    }
  else
    {
      struct passwd *pw = getpwnam(server_user);
      if (pw)
        {
          if (!pw->pw_passwd || !pw->pw_passwd[0])
            no_password = 1;
        }
    }

  return no_password;
}
