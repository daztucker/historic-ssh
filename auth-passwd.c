/*

auth-passwd.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar 18 05:11:38 1995 ylo

Password authentication.  This file contains the functions to check whether
the password is valid for the user.

*/

/*
 * $Id: auth-passwd.c,v 1.7 1995/09/10 22:44:41 ylo Exp $
 * $Log: auth-passwd.c,v $
 * Revision 1.7  1995/09/10  22:44:41  ylo
 * 	Added OSF/1 C2 extended security stuff.
 *
 * Revision 1.6  1995/08/21  23:20:29  ylo
 * 	Fixed a typo.
 *
 * Revision 1.5  1995/08/19  13:15:56  ylo
 * 	Changed securid code to initialize itself only once.
 *
 * Revision 1.4  1995/08/18  22:42:51  ylo
 * 	Added General Dynamics SecurID support from Donald McKillican
 * 	<dmckilli@qc.bell.ca>.
 *
 * Revision 1.3  1995/07/13  01:12:34  ylo
 * 	Removed the "Last modified" header.
 *
 * Revision 1.2  1995/07/13  01:09:50  ylo
 * 	Added cvs log.
 *
 * $Endlog$
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

#ifdef HAVE_SECURID
/* Support for Security Dynamics SecurID card.
   Contributed by Donald McKillican <dmckilli@qc.bell.ca>. */
#define SECURID_USERS "/etc/securid.users"
#include "sdi_athd.h"
#include "sdi_size.h"
#include "sdi_type.h"
#include "sdacmvls.h"
#include "sdconf.h"
union config_record configure;
static int securid_initialized = 0;
#endif /* HAVE_SECURID */

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
#ifdef HAVE_SECURID
  /* Support for Security Dynamics SecurId card.
     Contributed by Donald McKillican <dmckilli@qc.bell.ca>. */
  {
    /*
     * the way we decide if this user is a securid user or not is
     * to check to see if they are included in /etc/securid.users
     */
    int found = 0;
    FILE *securid_users = fopen(SECURID_USERS, "r");
    char *c;
    char su_user[257];
    
    if (securid_users)
      {
	while (fgets(su_user, sizeof(su_user), securid_users))
	  {
	    if (c = strchr(su_user, '\n')) 
	      *c = '\0';
	    if (strcmp(su_user, server_user) == 0) 
	      { 
		found = 1; 
		break; 
	      }
	  }
      }
    fclose(securid_users);

    if (found)
      {
	/* The user has a SecurID card. */
	struct SD_CLIENT sd_dat, *sd;
	log("SecurID authentication for %.100s required.", server_user);

	/*
	 * if no pass code has been supplied, fail immediately: passing
	 * a null pass code to sd_check causes a core dump
	 */
	if (*password == '\0') 
	  {
	    log("No pass code given, authentication rejected.");
	    return 0;
	  }

	sd = &sd_dat;
	if (!securid_initialized)
	  {
	    memset(&sd_dat, 0, sizeof(sd_dat));   /* clear struct */
	    creadcfg();		/*  accesses sdconf.rec  */
	    if (sd_init(sd)) 
	      packet_disconnect("Cannot contact securid server.");
	    securid_initialized = 1;
	  }
	return sd_check(password, server_user, sd) == ACM_OK;
      }
  }
  /* If the user has no SecurID card specified, we fall to normal 
     password code. */
#endif /* HAVE_SECURID */

  /* Save the encrypted password. */
  strncpy(correct_passwd, pw->pw_passwd, sizeof(correct_passwd));

#ifdef HAVE_OSF1_C2_SECURITY
    osf1c2_getprpwent(correct_passwd, pw->pw_name, sizeof(correct_passwd));
#else /* HAVE_OSF1_C2_SECURITY */
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
#endif /* HAVE_OSF1_C2_SECURITY */

  /* Check for users with no password. */
  if (strcmp(password, "") == 0 && strcmp(correct_passwd, "") == 0)
    {
      packet_send_debug("Login permitted without a password because the account has no password.");
      return 1; /* The user has no password and an empty password was tried. */
    }

  /* Encrypt the candidate password using the proper salt. */
#ifdef HAVE_OSF1_C2_SECURITY
  encrypted_password = (char *)osf1c2crypt(password,
                                   (correct_passwd[0] && correct_passwd[1]) ?
                                   correct_passwd : "xx");
#else /* HAVE_OSF1_C2_SECURITY */
  encrypted_password = crypt(password, 
			     (correct_passwd[0] && correct_passwd[1]) ?
			     correct_passwd : "xx");
#endif

  /* Authentication is accepted if the encrypted passwords are identical. */
  return strcmp(encrypted_password, correct_passwd) == 0;
}
