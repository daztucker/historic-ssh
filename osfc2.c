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
 * $Id: osfc2.c,v 1.11 1998/05/23 20:31:56 kivinen Exp $
 * $Log: osfc2.c,v $
 * Revision 1.11  1998/05/23  20:31:56  kivinen
 * 	Added osf1c2_check_account_and_terminal function.
 *
 * Revision 1.10  1998/05/11  21:26:49  kivinen
 * 	Moved prpasswd stuff to be inside if (pr).
 *
 * Revision 1.9  1998/05/11 18:53:16  kivinen
 * 	Fixed osf1 resource code, by moving resoure limit
 * 	initialization to initialize_osf_security function.
 * 	osf1c2_getprpwent function is only called if password
 * 	authentication is used, and because of this all limits
 * 	contained zero. This caused sshd client immediately exit
 * 	because of cpu resource limit exceeded.
 *
 * Revision 1.8  1998/04/30 01:53:57  kivinen
 * 	Fixed osflim handling so that now it allows setting resource
 * 	to 0.
 *
 * Revision 1.7  1998/03/30 21:39:40  kivinen
 * 	Added system default lock check.
 *
 * Revision 1.6  1998/03/27 16:58:42  kivinen
 * 	Fixed password expire code.
 *
 * Revision 1.5  1998/01/14 16:39:10  kivinen
 * 	Added check that getespwnam function exists.
 *
 * Revision 1.4  1998/01/02 06:19:31  kivinen
 * 	Added account locking and expiration support. Added resource
 * 	limit setting.
 *
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
#include "ssh.h"
#include <sys/security.h>
#include <prot.h>
#include <sia.h>

static int	c2security = -1;
static int	crypt_algo;
long		osflim[8];

void
initialize_osf_security(int ac, char **av)
{
  FILE *f;
  char buf[256];
  char siad[] = "siad_ses_init=";
  int i;

  for (i = 0; i < 8; i++)
    osflim[i] = -1;

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
	  else if (strstr(buf, "BSD") != NULL)
	    c2security = 0;
	  break;
	}
    }
  fclose(f);
  if (c2security == -1)
    {
      fprintf(stderr, "C2 security initialization failed : could not determine security level.\n");
      exit(1);
    }
  log_msg("OSF/1: security level : %s", c2security == 0 ? "BSD" : "C2");
  if (c2security == 1)
    set_auth_parameters(ac, av);
}

const char *osf1c2_check_account_and_terminal(const char *username,
					      const char *terminal)
{
  if (c2security == 1)
    {
      struct pr_passwd *pr = getprpwnam((char *) username);
      if (pr)
	{
	  if (pr->uflg.fg_lock == 1)
	    {
	      if (pr->ufld.fd_lock == 1)
		{
		  return "\n\tYour account is locked.\n\n";
		}
	    }
	  else
	    if (pr->sflg.fg_lock == 1 && pr->sfld.fd_lock == 1)
	      {
		return "\n\tYour account is locked.\n\n";
	      }
		
	  if (pr->uflg.fg_retired)
	    {
	      if (pr->ufld.fd_retired)
		{
		  return "\n\tYour account has been retired.\n\n";
		}
	    }
	  else
	    if (pr->sflg.fg_retired && pr->sfld.fd_retired)
	      {
		return "\n\tYour account has been retired.\n\n";
	      }
	  
#ifdef HAVE_TIME_LOCK
	  if (time_lock(pr))
	    {
	      return "\n\tWrong time period to log into this account.\n\n";
	    }
#endif /* HAVE_TIME_LOCK */
	  if (pr->uflg.fg_template)
	    {
#ifdef HAVE_GETESPWNAM
	      struct es_passwd *es = getespwnam(pr->ufld.fd_template);
	      if (es)
		{
#ifdef HAVE_GETESTCNAM
		  if (terminal != NULL)
		    {
		      struct es_term *term = getestcnam(terminal);
		      if (term)
			{
			  if (auth_for_terminal_es(es, term))
			    {
			      return "\n\tNot authorized to login from that terminal.\n\n";
			    }
			}
		    }
#endif /* HAVE_GETESTCNAM */
#ifdef HAVE_LOCKED_OUT_ES
		  if (locked_out_es(es))
		    {
		      return "\n\tYour account has been locked out.\n\n";
		    }
#endif /* HAVE_LOCKED_OUT_ES */
		  
		  /** Login resources **/
		  if (es->uflg->fg_rlim_cpu == 1) 
		    osflim[0] = es->ufld->fd_rlim_cpu;
		  if (es->uflg->fg_rlim_fsize == 1)
		    osflim[1] = es->ufld->fd_rlim_fsize;
		  if (es->uflg->fg_rlim_data == 1)
		    osflim[2] = es->ufld->fd_rlim_data;
		  if (es->uflg->fg_rlim_stack== 1)
		    osflim[3] = es->ufld->fd_rlim_stack;
		  if (es->uflg->fg_rlim_core == 1)
		    osflim[4] = es->ufld->fd_rlim_core;
		  if (es->uflg->fg_rlim_rss == 1)
		    osflim[5] = es->ufld->fd_rlim_rss;
		  if (es->uflg->fg_rlim_nofile == 1)
		    osflim[6] = es->ufld->fd_rlim_nofile;
		  if (es->uflg->fg_rlim_vmem == 1)
		    osflim[7] = es->ufld->fd_rlim_vmem;
		}
#endif /* HAVE_GETESPWNAM */
	    }
	}
    }
  return NULL;
}

int
osf1c2_getprpwent(char *p, char *n, int len)
{
  time_t pschg, tnow;

  if (c2security == 1)
    {
      struct es_passwd *es; 
      struct pr_passwd *pr = getprpwnam(n);
      if (pr)
	{
	  extern int days_before_password_expires;
	  
	  strncpy(p, pr->ufld.fd_encrypt, len);
	  crypt_algo = pr->ufld.fd_oldcrypt;

	  tnow = time(NULL);
	  if (pr->uflg.fg_schange == 1)
	    pschg = pr->ufld.fd_schange;
	  else
	    pschg = 0;
	  if (pr->uflg.fg_template == 0)
	    {
	      /** default template, system values **/
	      if (pr->sflg.fg_lifetime == 1)
		if (pr->sfld.fd_lifetime > 0 && 
		    pschg + pr->sfld.fd_lifetime < tnow)
		  return 1;
	      if (pr->sflg.fg_lifetime && pr->sfld.fd_lifetime > 0)
		days_before_password_expires =
		  (pschg + pr->sfld.fd_lifetime - tnow) / 86400;
	    }
	  else                      /** user template, specific values **/
	    {
#ifdef HAVE_GETESPWNAM
	      es = getespwnam(pr->ufld.fd_template);
	      if (es)
		{
		  if (es->uflg->fg_expire == 1) 
		    if (es->ufld->fd_expire > 0 &&
			pschg + es->ufld->fd_expire < tnow)
		      return 1;
		  if (es->uflg->fg_expire == 1 &&
		      es->ufld->fd_expire > 0)
		    days_before_password_expires =
		      (pschg + es->ufld->fd_expire - tnow) / 86400;
		  
		}
#endif /* HAVE_GETESPWNAM */
	    }
	}
    }
  else
    {
      struct passwd *pw = getpwnam(n);
      if (pw)
	strncpy(p, pw->pw_passwd, len);
    }
  return 0;
}

char *
osf1c2crypt(const char *pw, char *salt)
{
   if (c2security == 1) {
     return(dispcrypt(pw, salt, crypt_algo));
   } else
     return(crypt(pw, salt));
}
