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
 * $Id: auth-passwd.c,v 1.17 1998/06/11 00:03:38 kivinen Exp $
 * $Log: auth-passwd.c,v $
 * Revision 1.17  1998/06/11 00:03:38  kivinen
 * 	Added username to /bin/password commands.
 *
 * Revision 1.16  1998/05/23  20:19:40  kivinen
 * 	Removed #define uint32 rpc_unt32, because md5 uint32 is now
 * 	md5_uint32. Changed () -> (void). Changed osf1c2_getprpwent
 * 	function to return true/false. Added
 * 	forced_empty_passwd_change support.
 *
 * Revision 1.15  1998/05/11  21:27:47  kivinen
 * 	Set correct_passwd to contain 255...255 so even if some
 * 	function doesn't set it, it cannot contain empty password.
 *
 * Revision 1.14  1998/04/30 01:50:20  kivinen
 * 	Added code that will force /bin/passwd command if password is
 * 	expired.
 *
 * Revision 1.13  1998/03/27 16:53:09  kivinen
 * 	Added aix authenticate function support.
 *
 * Revision 1.12  1998/01/02 06:14:31  kivinen
 * 	Fixed kerberos ticket name handling. Added OSF C2 account
 * 	locking and expiration support.
 *
 * Revision 1.11  1997/04/17 03:57:05  kivinen
 * 	Kept FILE: prefix in kerberos ticket filename as DCE cache
 * 	code requires it (patch from Doug Engert <DEEngert@anl.gov>).
 *
 * Revision 1.10  1997/04/05 21:45:25  kivinen
 * 	Changed verify_krb_v5_tgt to take *error_code instead of
 * 	error_code.
 *
 * Revision 1.9  1997/03/27 03:09:20  kivinen
 * 	Added kerberos patches from Glenn Machin.
 *
 * Revision 1.8  1997/03/26 06:59:18  kivinen
 * 	Changed uid 0 to UID_ROOT.
 *
 * Revision 1.7  1997/03/19 15:57:21  kivinen
 * 	Added SECURE_RPC, SECURE_NFS and NIS_PLUS support from Andy
 * 	Polyakov <appro@fy.chalmers.se>.
 *
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

#ifdef SECURE_RPC
/*
 * refer to ftp://playground.sun.com/pub/rpc/tirpcsrc2.3.tar.Z for
 * detailed information about stuff you can't find in manual pages:-)
 */
#ifdef KEYBYTES
#undef KEYBYTES       /* conflicts with blowfish.h */
#endif

#include <rpc/rpc.h>
#include <rpc/key_prot.h>

static uid_t uid_keylogged = 0;

#ifdef SECURE_NFS
#include <nfs/export.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>

void nfs_revauth(uid_t uid)
{
  struct nfs_revauth_args _nfssysarg;
  
  _nfssysarg.authtype = AUTH_DES;
  _nfssysarg.uid      = uid;
  _nfssys (NFS_REVAUTH,&_nfssysarg);
}
#endif /* SECURE_NFS */

/* do /usr/bin/keylogout's job */
/* caller sets effective uid!  */
void keylogout(void)
{
  char secret [HEXKEYBYTES];
  
  if (!uid_keylogged || uid_keylogged != geteuid())
    return;
  
  /* revoke secret key from keyserv(1m) */
  memset(secret, '\0', sizeof(secret));
  key_setsecret(secret);     /* this one is keyserv.1 interface,
				but it does the job even for keyserv.2
				and takes the only argument:-) */
#ifdef SECURE_NFS
  /* as well as from nfs client module */
  nfs_revauth(uid_keylogged);
#endif /* SECURE_NFS */
  
  uid_keylogged = 0;
}

void keylogout_atexit (void)
{
  if (!uid_keylogged || seteuid(uid_keylogged))
    return;
  keylogout();
  seteuid(UID_ROOT);
}

#ifdef KEY_VERS2      /* keyserv protocol version 2 */
int my_secretkey_is_set(char *netname)
{
  return key_secretkey_is_set();
}
#else /* KEY_VERS2 */
/*
 * for keyserv.1 we just try to encrypt a session key to talk to ourselves.
 * this should fail if keyserv doesn't have our secret key. well, we can't
 * say if it's the right one, but we can't do any better anyway:-)
 */
int my_secretkey_is_set(char *netname)
{
  des_block block;
  memcpy (block.c, netname, sizeof(block.c));   /* well, whatever... */
  return (key_encryptsession(netname, &block) == 0);
}
#endif /* KEY_VERS2 */

/* do /usr/bin/keylogin's job */
/* caller sets effective uid! */
int keylogin(const char *passwd)
{
  int  ret = 0;
  char netnam[MAXNETNAMELEN+1], phrase[9];
#ifdef KEY_VERS2
  key_netstarg key_setnet_arg;
#define secret key_setnet_arg.st_priv_key
#define public key_setnet_arg.st_pub_key
  key_setnet_arg.st_netname = netnam;
#else /* KEY_VERS2 */
  char secret[HEXKEYBYTES], public[HEXKEYBYTES];
#endif /* KEY_VERS2 */
  
  if (getnetname(netnam) &&	/* do i exists?            */
      !(ret = my_secretkey_is_set(netnam)) && /* is it already set?      */
      passwd)			/* do i have the password? */
    {
      strncpy(phrase, passwd, 8);
      phrase[8] = '\0';
      memset(public, '\0', sizeof(public));
      memset(secret, '\0', sizeof(secret));
      if (getsecretkey(netnam, secret, phrase) && *secret)
	{
#ifdef KEY_VERS2
	  /*
	   * key_setnet is keyserv.2 interface and is not documented,
	   * but used by keylogin(1). and it's real mess with return
	   * values:-( so far, namely up to Solaris 2.5.1, it returns
	   * 1 on success and -1 when fails.
	   */
	  if (ret = (key_setnet(&key_setnet_arg) > 0))
#else /* KEY_VERS2 */
	  if (ret = !key_setsecret(secret))
#endif /* KEY_VERS2 */
	    {
	      uid_keylogged = geteuid(); /* save it for keylogout */
	      atexit(keylogout_atexit); /* clean up after ourselves */
	    }
	  memset(secret, '\0', sizeof (secret));
	}
      memset(phrase, '\0', sizeof(phrase));
    }
  return ret; /* secret key was set by whomever */
}
#endif /* SECURE_RPC */

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

#ifdef KERBEROS
#if defined(KRB5)
#include <krb5.h>
extern  krb5_context ssh_context;
extern  krb5_auth_context auth_context;
#else
#include <krb.h>
#endif /* KRB5 */
#endif /* KERBEROS */

#ifdef AFS
#include <afs/param.h>
#include <afs/kautils.h>
#endif /* AFS */

#if defined(KERBEROS) || defined(AFS_KERBEROS)
extern char *ticket;
#endif /* KERBEROS || AFS_KERBEROS */

/* Tries to authenticate the user using password.  Returns true if
   authentication succeeds. */

#if defined(KERBEROS) && defined(KRB5)
/*
 * This routine with some modification is from the MIT V5B6 appl/bsd/login.c
 *
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).  If the host/<host> service is unknown (i.e.,
 * the local keytab doesn't have it), let her in.
 *
 * Returns 1 for confirmation, -1 for failure, 0 for uncertainty.
 */
static
int verify_krb_v5_tgt (krb5_context c, krb5_ccache ccache,
		       krb5_error_code *error_code)
{
  char phost[BUFSIZ];
  int retval, have_keys;
  krb5_principal princ;
  krb5_keyblock *kb = 0;
  krb5_error_code krbval;
  krb5_data packet;
  krb5_auth_context auth_context = NULL;
  krb5_ticket *ticket = NULL;
  
  /* Set packet.data so that we do not free bogus memory below */
  packet.data = 0;
  
  /* get the server principal for the local host */
  /* (use defaults of "host" and canonicalized local name) */
  krbval = krb5_sname_to_principal(c, 0, 0, KRB5_NT_SRV_HST, &princ);
  if (krbval)
    {
      *error_code = krbval;
      return -1;
    }
  
  /* since krb5_sname_to_principal has done the work for us, just
     extract the name directly */
  strncpy(phost, krb5_princ_component(c, princ, 1)->data, BUFSIZ);
  
  /* Do we have host/<host> keys? */
  /* (use default keytab, kvno IGNORE_VNO to get the first match,
     and enctype is currently ignored anyhow.) */
  krbval = krb5_kt_read_service_key (c, NULL, princ, 0,
				     ENCTYPE_DES_CBC_CRC, &kb);
  if (kb)
    krb5_free_keyblock (c, kb);
  /* any failure means we don't have keys at all. */
  have_keys = krbval ? 0 : 1;
  
  /* talk to the kdc and construct the ticket */
  krbval = krb5_mk_req(c, &auth_context, 0, "host", phost,
		       0, ccache, &packet);
  /* wipe the auth context for mk_req */
  if (auth_context)
    {
      krb5_auth_con_free(c, auth_context);
      auth_context = NULL;
    }
  if (krbval == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
    {
      /* we have a service key, so something should be 
	 in the database, therefore this error packet could
	 have come from an attacker. */
      if (have_keys)
	{
	  retval = -1;
	  goto EGRESS;
	}
      /* but if it is unknown and we've got no key, we don't
	 have any security anyhow, so it is ok. */
      else
	{
	  retval = 0;
	  goto EGRESS;
	}
    }
  else
    if (krbval)
      {
	*error_code = krbval;
	retval = -1;
	goto EGRESS;
      }
  /* got ticket, try to use it */
  krbval = krb5_rd_req(c, &auth_context, &packet, 
		       princ, NULL, NULL, &ticket);
  
  
  if (krbval)
    {
      if (!have_keys)
	/* The krb5 errors aren't specified well, but I think
	   these values cover the cases we expect.  */
	switch (krbval)
	  {
	    /* no keytab */
	  case KRB5_KT_NOTFOUND:
	  case ENOENT:
	    /* keytab found, missing entry */
	    retval = 0;
	    break;
	  default:
	    /* unexpected error: fail */
	    retval = -1;
	    break;
	  }
      else
	/* Any error here is bad.  */
	retval = -1;
      *error_code = krbval;
      goto EGRESS;
    }
  /*
   * The host/<host> ticket has been received _and_ verified.
   */
  retval = 1;
  /* do cleanup and return */
EGRESS:
  if (auth_context)
    krb5_auth_con_free(c, auth_context);
  if (ticket)
    krb5_free_ticket(c, ticket);
  if (packet.data)
    {
      free(packet.data);
      packet.data = 0;
    }
  krb5_free_principal(c, princ);
  /* possibly ticket and packet need freeing here as well */
  /* memset (&ticket, 0, sizeof (ticket)); */
  return retval;
}

krb5_data tgtname = {
  0,
  KRB5_TGS_NAME_SIZE,
  KRB5_TGS_NAME
};

/*
 * Preauthentication types should be listed prior to 0.
 * The last one tried will be no preauthentication
 * Type 5 is compatible with DCE timestamp
 * Type 2 is MIT current timestamp implementation
 */
#ifdef KRB5_PADATA_ENC_UNIX_TIME
krb5_preauthtype preauth_list[3] = { KRB5_PADATA_ENC_UNIX_TIME,
                                     KRB5_PADATA_ENC_TIMESTAMP,
                                     0 };
#else
krb5_preauthtype preauth_list[2] = { KRB5_PADATA_ENC_TIMESTAMP,
                                     0 };
#endif
krb5_preauthtype * preauth = preauth_list;
#endif /* KERBEROS */

/* Tries to authenticate the user using password.  Returns true if
   authentication succeeds. */
#ifdef KERBEROS
int auth_password(const char *server_user, const char *password,
		  krb5_principal client)
#else  /* KERBEROS */
int auth_password(const char *server_user, const char *password)
#endif /* KERBEROS */
{
#if defined(_AIX) && defined(HAVE_AUTHENTICATE)
  char *message;
  int reenter;

  reenter = 1;
  if (authenticate(server_user, password, &reenter, &message) == 0)
    {
      return 1;
    }
  else
    {
      return 0;
    }
#else /* _AIX41 && HAVE_AUTHENTICATE */

#ifdef KERBEROS
  krb5_error_code problem;
  int krb5_options = KDC_OPT_RENEWABLE | KDC_OPT_FORWARDABLE;
  krb5_deltat rlife = 0;
  krb5_principal server = 0;
  krb5_creds my_creds;
  krb5_timestamp now;
  krb5_ccache ccache;
  char ccname[80];
  int results;
#endif  /* KERBEROS */
  extern ServerOptions options;
  extern char *crypt(const char *key, const char *salt);
  struct passwd *pw;
  char *encrypted_password;
  char correct_passwd[200];
  char *saved_pw_name, *saved_pw_passwd;

  memset(correct_passwd, 255, sizeof(correct_passwd));
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
  
#if defined(KERBEROS)
  if (options.kerberos_authentication)
    {
#if defined(KRB5)
      sprintf(ccname, "FILE:/tmp/krb5cc_l%d", getpid());
      
      if (problem = krb5_cc_resolve(ssh_context, ccname, &ccache))
	goto errout2;
      
      if (problem = krb5_cc_initialize(ssh_context, ccache, client))
	goto errout;
      
      problem =
	krb5_build_principal_ext(ssh_context, &server,
				 krb5_princ_realm(ssh_context, client)->length,
				 krb5_princ_realm(ssh_context, client)->data,
				 tgtname.length, tgtname.data,
				 krb5_princ_realm(ssh_context, client)->length,
				 krb5_princ_realm(ssh_context, client)->data,
				 0);
      if (problem)
	goto errout;
      
      memset(&my_creds, 0, sizeof(my_creds));
      my_creds.client = client;
      my_creds.server = server;
      problem = krb5_timeofday(ssh_context, &now);
      if (problem)
	goto errout;
      my_creds.times.starttime = 0; /* start timer when
				       request gets to KDC */
      my_creds.times.endtime = now + 60*60*10;   /* 10 hours */
      
      problem = krb5_string_to_deltat("7d", &rlife); /* 7 days renew time */
      if (problem || rlife == 0)
        goto errout;
      
      my_creds.times.renew_till = now + rlife;
      
      
      problem = krb5_get_in_tkt_with_password(ssh_context, krb5_options, 0,
					      NULL, preauth,
					      password, ccache,
					      &my_creds, 0);
      
      /* If not successful try no preauthentication */
      if (problem)
	problem = krb5_get_in_tkt_with_password(ssh_context,
						krb5_options, 0,
						NULL, 0,
						password, ccache,
						&my_creds, 0);
      krb5_free_principal(ssh_context, server);
      server = 0;
      if (problem)
	goto errout;
      else
	{
	  /* Verify tgt just obtained */
	  results = verify_krb_v5_tgt(ssh_context, ccache, &problem);
	  
	  if (results  >= 0)
	    {
	      /* If results is 0 then put out a log message that
		 the TGT was not verified, pass this back to the
		 user as well */
	      if (results == 0)
		{
		  log_msg("TGT for user %s was not verified.", server_user);
		  packet_send_debug("Kerberos TGT could not be verified.");
		}
	      
            /* get_name pulls out just the name not the
               type */
	      strcpy(ccname + 5, krb5_cc_get_name(ssh_context, ccache));
	      (void) chown(ccname + 5, pw->pw_uid, pw->pw_gid);
	      
	      /* If tgt was passed unlink file */
	      if (ticket)
		{
		  if (strcmp(ticket,"none"))
		    /* ticket -> FILE:path */
		    unlink(ticket + 5);
		  else
                    ticket = NULL;
		}
	      
	      ticket = xmalloc(strlen(ccname) + 1);
	      (void) sprintf(ticket, "%s", ccname);
	      
	      /* We do not need this so free them up */
	      xfree(saved_pw_name);
	      xfree(saved_pw_passwd);
	      
	      return 1;
	    }
	  if (problem == KRB5_KT_NOTFOUND)
	    {
	      /* We have potential KDC spoofing here - log it */
	      log_msg("WARNING: Verification of TGT indicates potential KDC spoofing: user %s address %s", server_user, get_remote_ipaddr());
	      packet_send_debug("Verification of TGT indicates potential KDC spoofing.");
	    }
	}
    errout:
      krb5_cc_destroy (ssh_context, ccache);
    errout2:
      if (problem)
	{
	  log_msg("Password authentication of user %s using Kerberos failed: %s",
		  server_user, error_message(problem));
	  if (server) 
	    krb5_free_principal(ssh_context, server);
	  if (!options.kerberos_or_local_passwd )
	    {
	      /* We do not need this so free them up */
	      xfree(saved_pw_name);
	      xfree(saved_pw_passwd);
	      return 0;
	    }
	}
#endif /* KRB5 */
    }
#endif /* KERBEROS */
  
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

#ifdef SECURE_RPC
  /* try to register secret key for secure RPC */
  seteuid(pw->pw_uid);       /* just let it fail if ran by user */
  keylogin(password);
  seteuid(UID_ROOT);                /* just let it fail if ran by user */
#endif /* SECURE_RPC */

#ifdef HAVE_OSF1_C2_SECURITY
  if (osf1c2_getprpwent(correct_passwd, saved_pw_name,
			sizeof(correct_passwd)))
    {
      if (options.forced_passwd_change)
	{
	  extern char *forced_command;
	  forced_command = xmalloc(20 + strlen(server_user));
	  sprintf(forced_command, "/bin/passwd %s", server_user);
	  packet_send_debug("Password expired, forcing it to be changed.");
	}
      else
	{
	  packet_send_debug("\n\tYour password has expired.");
	}
    }
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
#if defined(SECURE_RPC) && defined(NIS_PLUS)
    if (!geteuid() && pw->pw_uid && /* do we have guts? */
	(!sp || !sp->sp_pwdp || !strcmp(sp->sp_pwdp,"*NP*")))
      if (seteuid(pw->pw_uid) == UID_ROOT)
	{
	  sp = getspnam(saved_pw_name); /* retry as user */   
	  seteuid(UID_ROOT);
	}
#endif /* SECURE_RPC && NIS_PLUS */
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
      if (options.forced_empty_passwd_change)
	{
	  extern char *forced_command;
	  forced_command = xmalloc(20 + strlen(server_user));
	  sprintf(forced_command, "/bin/passwd %s", server_user);
          packet_send_debug("Password if forced to be set at first login.");
	}
      else
	{
	  packet_send_debug("Login permitted without a password because the account has no password.");
	}
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
#endif /* _AIX && HAVE_AUTHENTICATE */
}
