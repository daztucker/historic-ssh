/*

osfc2.c

Author: Christophe Wolfhugel

Copyright (c) 1995 Christophe Wolfhugel

Free use of this file is permitted for any purpose as long as
this copyright is preserved in the header.

This program implements the use of the OSF/1 C2 security extensions
within ssh. See the file COPYING for full licensing informations.

*/

/*
 * $Id: osfc2.c,v 1.3 1997/01/08 13:22:36 ttsalo Exp $
 * $Log: osfc2.c,v $
 * Revision 1.3  1997/01/08 13:22:36  ttsalo
 * 	A fix for OSF/1 passwords from
 * 	Steve VanDevender <stevev@hexadecimal.uoregon.edu> merged.
 *
 * Revision 1.2  1996/10/29 22:43:02  kivinen
 * 	log -> log_msg.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:11  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.3  1995/09/10  23:27:28  ylo
 * 	Eliminated duplicate #includes.
 *
 * Revision 1.2  1995/09/10  23:03:56  ylo
 * 	Added copyright.
 *
 * Revision 1.1  1995/09/10  22:41:01  ylo
 * 	Support functions for OSF/1 C2 extended security
 * 	authentication.
 *
 */

#include "includes.h"
#include <sys/security.h>
#include <prot.h>
#include <sia.h>

static int	c2security = -1;
static int	crypt_algo;


void
initialize_osf_security(int ac, char **av)
{
  FILE *f;
  char buf[256];
  char siad[] = "siad_ses_init=";

  if (access(SIAIGOODFILE, F_OK) == -1) {
    /* Broken OSF/1 system, better don't run on it. */
    fprintf(stderr, "%s does not exist. Your OSF/1 system is probably broken.\n",
                    SIAIGOODFILE);
    exit(1);
  }
  if ((f = fopen(MATRIX_CONF, "r")) == NULL) {
    /* Another way OSF/1 is probably broken. */
    fprintf(stderr, "%s unreadable. Your OSF/1 system is probably broken.\n",
                    MATRIX_CONF); 
    exit(1);
  }

  /* Read matrix.conf to check if we run C2 or not */
  while (fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(buf, siad, sizeof(siad) - 1) == 0) {
      if (strstr(buf, "OSFC2") != NULL)
        c2security = 1;
      else if (strstr(buf, "BSD") != NULL)
        c2security = 0;
      break;
    }
  }
  fclose(f);
  if (c2security == -1) {
    fprintf(stderr, "C2 security initialization failed : could not determine security level.\n");
    exit(1);
  }
  log_msg("OSF/1: security level : %s", c2security == 0 ? "BSD" : "C2");
  if (c2security == 1)
     set_auth_parameters(ac, av);
}

void
osf1c2_getprpwent(char *p, char *n, int len)
{
   if (c2security == 1) {
     struct pr_passwd *pr = getprpwnam(n);
     if (pr) {
       strncpy(p, pr->ufld.fd_encrypt, len);
       crypt_algo = pr->ufld.fd_oldcrypt;
     }
   } else {
      struct passwd *pw = getpwnam(n);
      if (pw)
         strncpy(p, pw->pw_passwd, len);
   }
}

char *
osf1c2crypt(char *pw, char *salt)
{
   if (c2security == 1) {
     return(dispcrypt(pw, salt, crypt_algo));
   } else
     return(crypt(pw, salt));
}
