/*

auth-passwd.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar 18 05:11:38 1995 ylo
Last modified: Sun Jul  2 19:54:14 1995 ylo

Password authentication.  This file contains the functions to check whether
the password is valid for the user.

*/

#include "includes.h"
#ifdef HAVE_ETC_SHADOW
#include <shadow.h>
#endif /* HAVE_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#include "packet.h"
#include "ssh.h"

/* Tries to authenticate the user using password.  Returns true if
   authentication succeeds. */

int auth_password(const char *server_user, const char *password)
{
  extern char *crypt(const char *key, const char *salt);
  struct passwd *pw;
  char *encrypted_password;
  char correct_passwd[200];

  /* Get the encrypted password for the user. */
  pw = getpwnam(server_user);
  if (!pw)
    return 0;
  /* Save the encrypted password. */
  strncpy(correct_passwd, pw->pw_passwd, sizeof(correct_passwd));

  /* If we have shadow passwords, lookup the real encrypted password from
     the shadow file, and replace the saved encrypted password with the
     real encrypted password. */
#ifdef HAVE_ETC_SHADOW
  {
    struct spwd *sp = getspnam(pw->pw_name);
    if (sp)
      strncpy(correct_passwd, sp->sp_pwdp, sizeof(correct_passwd));
    endspent();
  }
#else /* HAVE_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
  {
    struct passwd_adjunct *sp = getpwanam(pw->pw_name);
    if (sp)
      strncpy(correct_passwd, sp->pwa_passwd, sizeof(correct_passwd));
    endpwaent();
  }
#else /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#ifdef HAVE_ETC_MASTER_PASSWD
  {
    char line[1024], user[200], passwd[200];
    FILE *f;
    f = fopen("/etc/master.passwd", "r");
    if (f)
      {
	while (fgets(line, sizeof(line), f))
	  {
	    if (sscanf(line, "%100[^:]:%100[^:]:", user, passwd) != 2)
	      continue;
	    if (strcmp(user, server_user) == 0)
	      {
		strncpy(correct_passwd, passwd, sizeof(correct_passwd));
		break;
	      }
	  }
	fclose(f);
      }
  }
#else /* HAVE_ETC_MASTER_PASSWD */
#ifdef HAVE_ETC_SECURITY_PASSWD
  {
    FILE *f;
    char line[1024], looking_for_user[200], *cp;
    int found_user = 0;
    f = fopen("/etc/security/passwd", "r");
    if (f)
      {
	sprintf(looking_for_user, "%.190s:", server_user);
	while (fgets(line, sizeof(line), f))
	  {
	    if (strchr(line, '\n'))
	      *strchr(line, '\n') = 0;
	    if (strcmp(line, looking_for_user) == 0)
	      found_user = 1;
	    else
	      if (line[0] != '\t' && line[0] != ' ')
		found_user = 0;
	      else
		if (found_user)
		  {
		    for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
		      ;
		    if (strncmp(cp, "password = ", strlen("password = ")) == 0)
		      {
			strncpy(correct_passwd, cp + strlen("password = "), 
				sizeof(correct_passwd));
			correct_passwd[sizeof(correct_passwd) - 1] = 0;
			break;
		      }
		  }
	  }
	fclose(f);
      }
  }
#endif /* HAVE_ETC_SECURITY_PASSWD */
#endif /* HAVE_ETC_MASTER_PASSWD */
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#endif /* HAVE_ETC_SHADOW */

  /* Check for users with no password. */
  if (strcmp(password, "") == 0 && strcmp(correct_passwd, "") == 0)
    {
      packet_send_debug("Login permitted without a password because the account has no password.");
      return 1; /* The user has no password and an empty password was tried. */
    }

  /* Encrypt the candidate password using the proper salt. */
  encrypted_password = crypt(password, 
			     (correct_passwd[0] && correct_passwd[1]) ?
			     correct_passwd : "xx");

  /* Authentication is accepted if the encrypted passwords are identical. */
  return strcmp(encrypted_password, correct_passwd) == 0;
}
