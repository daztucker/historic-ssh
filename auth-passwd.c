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
 * $Id: auth-passwd.c,v 1.6 1996/10/30 04:22:43 kivinen Exp $
 * $Log: auth-passwd.c,v $
 * Revision 1.6  1996/10/30 04:22:43  kivinen
 * 	Added #ifdef HAVE_SHADOW_H around shadow.h including.
 *
 * Revision 1.5  1996/10/29 22:33:59  kivinen
 * 	log -> log_msg.
 *
 * Revision 1.4  1996/10/08 13:50:44  ttsalo
 * 	Allow long passwords for HP-UX TCB authentication
 *
 * Revision 1.3  1996/09/08 17:36:51  ttsalo
 * 	Patches for HPUX 10.x shadow passwords from
 * 	vincent@ucthpx.uct.ac.za (Russell Vincent) merged.
 *
 * Revision 1.2  1996/02/18 21:53:45  ylo
 * 	Test for HAVE_ULTRIX_SHADOW_PASSWORDS instead of ultrix
 * 	(mips-dec-mach3 has ultrix defined, but does not support the
 * 	shadow password stuff).
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.8  1995/09/27  02:10:34  ylo
 * 	Added support for SCO unix shadow passwords.
 *
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
#ifdef HAVE_SCO_ETC_SHADOW
# include <sys/security.h>
# include <sys/audit.h>
# include <prot.h>
#else /* HAVE_SCO_ETC_SHADOW */
#ifdef HAVE_HPUX_TCB_AUTH
# include <sys/types.h>
# include <hpsecurity.h>
# include <prot.h>
#else /* HAVE_HPUX_TCB_AUTH */
#ifdef HAVE_ETC_SHADOW
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif
#endif /* HAVE_ETC_SHADOW */
#endif /* HAVE_HPUX_TCB_AUTH */
#endif /* HAVE_SCO_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#ifdef HAVE_ULTRIX_SHADOW_PASSWORDS
#include <auth.h>
#include <sys/svcinfo.h>
#endif /* HAVE_ULTRIX_SHADOW_PASSWORDS */
#include "packet.h"
#include "ssh.h"
#include "servconf.h"
#include "xmalloc.h"

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
  extern ServerOptions options;
  extern char *crypt(const char *key, const char *salt);
  struct passwd *pw;
  char *encrypted_password;
  char correct_passwd[200];
  char *saved_pw_name, *saved_pw_passwd;

  if (*password == '\0' && options.permit_empty_passwd == 0)
  {
      packet_send_debug("Server does not permit empty password login.");
      return 0;
  }

  /* Get the encrypted password for the user. */
  pw = getpwnam(server_user);
  if (!pw)
    return 0;
  saved_pw_name = xstrdup(pw->pw_name);
  saved_pw_passwd = xstrdup(pw->pw_passwd);
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
	log_msg("SecurID authentication for %.100s required.", server_user);

	/*
	 * if no pass code has been supplied, fail immediately: passing
	 * a null pass code to sd_check causes a core dump
	 */
	if (*password == '\0') 
	  {
	    log_msg("No pass code given, authentication rejected.");
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
  strncpy(correct_passwd, saved_pw_passwd, sizeof(correct_passwd));

#ifdef HAVE_OSF1_C2_SECURITY
    osf1c2_getprpwent(correct_passwd, saved_pw_name, sizeof(correct_passwd));
#else /* HAVE_OSF1_C2_SECURITY */
  /* If we have shadow passwords, lookup the real encrypted password from
     the shadow file, and replace the saved encrypted password with the
     real encrypted password. */
#if defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH)
  {
    struct pr_passwd *pr = getprpwnam(saved_pw_name);
    pr = getprpwnam(saved_pw_name);
    if (pr)
      strncpy(correct_passwd, pr->ufld.fd_encrypt, sizeof(correct_passwd));
    endprpwent();
  }
#else /* defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH) */
#ifdef HAVE_ETC_SHADOW
  {
    struct spwd *sp = getspnam(saved_pw_name);
    if (sp)
      strncpy(correct_passwd, sp->sp_pwdp, sizeof(correct_passwd));
    endspent();
  }
#else /* HAVE_ETC_SHADOW */
#ifdef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
  {
    struct passwd_adjunct *sp = getpwanam(saved_pw_name);
    if (sp)
      strncpy(correct_passwd, sp->pwa_passwd, sizeof(correct_passwd));
    endpwaent();
  }
#else /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
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
#endif /* HAVE_ETC_SECURITY_PASSWD_ADJUNCT */
#endif /* HAVE_ETC_SHADOW */
#endif /* HAVE_SCO_ETC_SHADOW */
#endif /* HAVE_OSF1_C2_SECURITY */

  /* Check for users with no password. */
  if (strcmp(password, "") == 0 && strcmp(correct_passwd, "") == 0)
    {
      packet_send_debug("Login permitted without a password because the account has no password.");
      return 1; /* The user has no password and an empty password was tried. */
    }

  xfree(saved_pw_name);
  xfree(saved_pw_passwd);

#ifdef HAVE_ULTRIX_SHADOW_PASSWORDS
  {
    /* Note: we are assuming that pw from above is still valid. */
    struct svcinfo *svp;
    svp = getsvc();
    if (svp == NULL)
      {
	error("getsvc() failed in ultrix code in auth_passwd");
	return 0;
      }
    if ((svp->svcauth.seclevel == SEC_UPGRADE &&
	 strcmp(pw->pw_passwd, "*") == 0) ||
	svp->svcauth.seclevel == SEC_ENHANCED)
      return authenticate_user(pw, password, "/dev/ttypXX") >= 0;
  }
#endif /* HAVE_ULTRIX_SHADOW_PASSWORDS */

  /* Encrypt the candidate password using the proper salt. */
#ifdef HAVE_OSF1_C2_SECURITY
  encrypted_password = (char *)osf1c2crypt(password,
                                   (correct_passwd[0] && correct_passwd[1]) ?
                                   correct_passwd : "xx");
#else /* HAVE_OSF1_C2_SECURITY */
#if defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH)
  encrypted_password = bigcrypt(password, 
			     (correct_passwd[0] && correct_passwd[1]) ?
			     correct_passwd : "xx");
#else /* defined(HAVE_SCO_ETC_SHADOW) || defined(HAVE_HPUX_TCB_AUTH) */
  encrypted_password = crypt(password, 
			     (correct_passwd[0] && correct_passwd[1]) ?
			     correct_passwd : "xx");
#endif /* HAVE_SCO_ETC_SHADOW */
#endif /* HAVE_OSF1_C2_SECURITY */

  /* Authentication is accepted if the encrypted passwords are identical. */
  return strcmp(encrypted_password, correct_passwd) == 0;
}
