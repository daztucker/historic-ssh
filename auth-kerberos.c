/*

   auth-kerberos.c

   Initally written by Dug Song <dugsong@umich.edu> for Kerberos V4.
   Mapped over to user Kerberos V5 by Glenn Machin - Sandia Natl Labs

   Kerberos authentication and ticket-passing routines.

*/
/*
 * $Id: auth-kerberos.c,v 1.2 1997/04/17 03:56:51 kivinen Exp $
 * $Log: auth-kerberos.c,v $
 * Revision 1.2  1997/04/17 03:56:51  kivinen
 * 	Kept FILE: prefix in kerberos ticket filename as DCE cache
 * 	code requires it (patch from Doug Engert <DEEngert@anl.gov>).
 *
 * Revision 1.1  1997/03/27 03:09:29  kivinen
 * *** empty log message ***
 *
 *
 * $Endlog$
 */

#include "includes.h"
#include "packet.h"
#include "xmalloc.h"
#include "ssh.h"

#ifdef KERBEROS
#if defined (KRB5)
#include <krb5.h>

extern  krb5_context ssh_context;
extern  krb5_auth_context auth_context;

int auth_kerberos(char *server_user, krb5_data *auth, krb5_principal *client)
{
  krb5_error_code problem;
  krb5_ticket *ticket;
  krb5_data reply;
  krb5_principal tkt_client;
  char *server = 0;
  
  memset(&reply, 0, sizeof(reply));
  
  if (auth_context)
    krb5_auth_con_free(ssh_context, auth_context);

  auth_context = 0;
  krb5_auth_con_init(ssh_context, &auth_context);
  problem =
    krb5_auth_con_genaddrs(ssh_context, auth_context,
			   packet_get_connection_in(),
			   KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR);
  if (problem)
    {
      if (auth_context)
	{
	  krb5_auth_con_free(ssh_context, auth_context);
	  auth_context = 0;
	}
      log_msg("Kerberos ticket authentication of user %s failed: %s",
	      server_user, error_message(problem));
      
      debug("Kerberos krb5_auth_con_genaddrs (%s).", error_message(problem));
      packet_send_debug("Kerberos krb5_auth_con_genaddrs: %s",
			error_message(problem));
      return 0;
    }
  problem = krb5_rd_req(ssh_context, &auth_context, auth,
			NULL, NULL, NULL, &ticket);
  if (problem)
    {
      if (auth_context)
	{
	  krb5_auth_con_free(ssh_context, auth_context);
	  auth_context = 0;  
	}
      log_msg("Kerberos ticket authentication of user %s failed: %s",
	      server_user, error_message(problem));
      
      debug("Kerberos V5 rd_req failed (%s).", error_message(problem));
      packet_send_debug("Kerberos V5 krb5_rd_req: %s", error_message(problem));
      return 0;
    }
  
  /* Verify from ticket that the server used was of the form host/system */
  problem = krb5_unparse_name(ssh_context, ticket->server, &server);
  if (problem)
    {
      krb5_free_ticket(ssh_context, ticket);
      log_msg("Kerberos ticket authentication of user %s failed: %s",
	      server_user, error_message(problem));
      
      debug("Kerberos krb5_unparse_name failed (%s).", error_message(problem));
      packet_send_debug("Kerberos krb5_unparse_name: %s",
			error_message(problem));
      return 0;
    }
  if (strncmp(server, "host/", strlen("host/")))
    {
      krb5_free_ticket(ssh_context, ticket);
      log_msg("Kerberos ticket authentication of user %s failed: invalid service name (%s)",
	      server_user, server);
      
      debug("Kerberos invalid service name (%s).", server);
      packet_send_debug("Kerberos invalid service name (%s).", server);
      krb5_xfree(server);
      return 0;
    }
  krb5_xfree(server);
  
  /* Extract the users name from the ticket client principal */
  problem = krb5_copy_principal(ssh_context, ticket->enc_part2->client,
				&tkt_client);
  
  krb5_free_ticket(ssh_context, ticket);
  
  if (problem)
    {
      log_msg("Kerberos ticket authentication of user %s failed: %s",
	      server_user, error_message(problem));
      debug("Kerberos krb5_copy_principal failed (%s).", 
	    error_message(problem));
      packet_send_debug("Kerberos krb5_copy_principal: %s", 
			error_message(problem));
      return 0;
    }
  *client = tkt_client;
  
  /* Make the reply - so that mutual authentication can be done */
  if ((problem = krb5_mk_rep(ssh_context, auth_context, &reply)))
    {
      log_msg("Kerberos ticket authentication of user %s failed: %s",
	      server_user, error_message(problem));
      debug("Kerberos krb5_mk_rep failed (%s).",
	    error_message(problem));
      packet_send_debug("Kerberos krb5_mk_rep failed: %s",
			error_message(problem));
      return 0;
    }
  
  packet_start(SSH_SMSG_AUTH_KERBEROS_RESPONSE);
  packet_put_string((char *) reply.data, reply.length);
  packet_send();
  packet_write_wait();
  krb5_xfree(reply.data);
  return 1;
}
#endif /* KRB5 */
#endif /* KERBEROS */

#ifdef KERBEROS_TGT_PASSING
#if defined (KRB5)
int auth_kerberos_tgt( char *server_user, krb5_data *krb5data)
{
  krb5_creds **creds;
  krb5_error_code retval;
  static char ccname[128];
  krb5_ccache ccache = NULL;
  struct passwd *pwd;
  extern char *ticket;
  static krb5_principal rcache_server = 0;
  static krb5_rcache rcache;
  struct sockaddr_in local, foreign;
  krb5_address *local_addr, *remote_addr;
  int s;
  
  if (!(pwd = (struct passwd *) getpwnam(server_user)))
    {
      log_msg("Kerberos V5 tgt rejected for user %.100s", server_user);
      packet_send_debug("Kerberos V5 tgt rejected for %.100s", server_user);
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
      return 0;
    }
  
  if (!auth_context)
    {
      if (!rcache_server)
	krb5_parse_name(ssh_context,"sshd", &rcache_server);
      krb5_auth_con_init(ssh_context, &auth_context);
      
      /* Set the addresses for local and remote systems, and replay
         cache */
      
      /* GDM : We need to establish the local addresses and remote addresses
         within auth_context, in order to to TGT forwarding. Normally
         when the authentication credentials are passed, these are 
         established then, however in SSH the forwarded TGT is 
         passed prior to authentication. (Needed by AFS) */
      
      s = packet_get_connection_in();
      krb5_auth_con_genaddrs(ssh_context, auth_context, s, 
			     KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR |
			     KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR);
      krb5_get_server_rcache(ssh_context,
			     krb5_princ_component(context, rcache_server, 0),
			     &rcache);
      krb5_auth_con_setrcache( ssh_context, auth_context, rcache);
      
    }
  
  if (retval = krb5_rd_cred(ssh_context, auth_context, krb5data, &creds, NULL))
    {
      log_msg("Kerberos V5 tgt rejected for user %.100s : %s", server_user,
	      error_message(retval));
      packet_send_debug("Kerberos V5 tgt rejected for %.100s : %s",
			server_user,
			error_message(retval));
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
      return 0;
    }
  
  sprintf(ccname, "FILE:/tmp/krb5cc_p%d", getpid());
  
  if (retval = krb5_cc_resolve(ssh_context, ccname, &ccache))
    goto errout;
  
  if (retval = krb5_cc_initialize(ssh_context, ccache, (*creds)->client))
    goto errout;
  
  if (retval = krb5_cc_store_cred(ssh_context, ccache, *creds))
    goto errout;
  
  if (retval = chown(ccname+5, pwd->pw_uid, -1))
    goto errout;
  
  ticket = xmalloc(strlen(ccname + 5) + 1);
  (void) sprintf(ticket, "%s", ccname);
  
  /* Successful */
  packet_start(SSH_SMSG_SUCCESS);
  packet_send();
  packet_write_wait();
  return 1;
  
errout:
  krb5_free_tgt_creds(ssh_context, creds);
  log_msg("Kerberos V5 tgt rejected for user %.100s :%s", server_user,
	  error_message(retval));
  packet_send_debug("Kerberos V5 tgt rejected for %.100s : %s", server_user,
		    error_message(retval));
  packet_start(SSH_SMSG_FAILURE);
  packet_send();
  packet_write_wait();
  return 0;
  
}
#endif /* KRB5 */
#endif /* KERBEROS_TGT_PASSING */

