/*

sshconnect.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar 18 22:15:47 1995 ylo

Code to connect to a remote host, and to perform the client side of the
login (authentication) dialog.

*/

/*
 * $Id: sshconnect.c,v 1.11 1995/09/13 12:03:55 ylo Exp $
 * $Log: sshconnect.c,v $
 * Revision 1.11  1995/09/13  12:03:55  ylo
 * 	Added debugging output to print uids.
 *
 * Revision 1.10  1995/09/10  22:48:29  ylo
 * 	Added original_real_uid parameter to ssh_login.  Changed to
 * 	use it.
 * 	Fixed read_passphrase arguments.
 *
 * Revision 1.9  1995/09/09  21:26:46  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.8  1995/09/06  16:01:12  ylo
 * 	Added BROKEN_INET_ADDR.
 *
 * Revision 1.7  1995/08/31  09:24:23  ylo
 * 	Fixed user_hostfile name processing.
 *
 * Revision 1.6  1995/08/21  23:29:32  ylo
 * 	Clear sockaddr_in before using.
 * 	Pass session_id and response_type to ssh_decrypt_challenge.
 *
 * Revision 1.5  1995/07/27  02:18:13  ylo
 * 	Tell packet_set_encryption_key that we are the client.
 *
 * Revision 1.4  1995/07/27  00:40:56  ylo
 * 	Added GlobalKnownHostsFile and UserKnownHostsFile.
 *
 * Revision 1.3  1995/07/26  23:19:20  ylo
 * 	Removed include version.h.
 *
 * 	Added code for protocol version 1.1.  This involves changes in
 * 	the session key exchange code and RSA responses to make
 * 	replay impossible and to bind RSA responses to a particular
 * 	session so that a corrupt server cannot pass them on to
 * 	another connection.  Moved rsa response code to a separate function.
 *
 * 	Fixed session key exchange to match the RFC draft.
 *
 * 	Prints a warning if server uses older protocol version (but
 * 	compatibility code still supports the older version).
 *
 * Revision 1.2  1995/07/13  01:40:32  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include <gmp.h>
#include "xmalloc.h"
#include "randoms.h"
#include "rsa.h"
#include "ssh.h"
#include "packet.h"
#include "authfd.h"
#include "cipher.h"
#include "md5.h"
#include "mpaux.h"

/* Maximum number of times to try connecting if the host returns
   ECONNREFUSED. */
#define MAX_CONNECTION_ATTEMPTS		4

/* This variable is set to true if remote protocol version is 1.1 or higher. 
   XXX remove this variable later. */
int remote_protocol_1_1 = 0;

/* Session id for the current session. */
unsigned char session_id[16];

/* Opens a TCP/IP connection to the remote server on the given host.  If
   port is 0, the default port will be used.  If anonymous is zero,
   a privileged port will be allocated to make the connection. 
   This requires super-user privileges if anonymous is false. */

int ssh_connect(const char *host, int port, int anonymous,
		uid_t original_real_uid)
{
  int sock, attempt, i;
  int on = 1;
  struct servent *sp;
  struct hostent *hp;
  struct sockaddr_in hostaddr;
#ifdef SO_LINGER
  struct linger linger;
#endif /* SO_LINGER */

  debug("ssh_connect: getuid %d geteuid %d anon %d", 
	(int)getuid(), (int)geteuid(), anonymous);

  /* Get default port if port has not been set. */
  if (port == 0)
    {
      sp = getservbyname(SSH_SERVICE_NAME, "tcp");
      if (sp)
	port = ntohs(sp->s_port);
      else
	port = SSH_DEFAULT_PORT;
    }

  /* No host lookup made yet. */
  hp = NULL;
  
  /* Try to connect several times.  On some machines, the first time will
     sometimes fail.  In general socket code appears to behave quite
     magically on many machines. */
  for (attempt = 0; attempt < MAX_CONNECTION_ATTEMPTS; attempt++)
    {
      if (attempt > 0)
	debug("Trying again...");
      
      /* Create a socket. */

      /* If we are running as root and want to connect to a privileged port,
	 bind our own socket to a privileged port. */
      if (!anonymous && geteuid() == 0 && port < 1024)
	{
	  struct sockaddr_in sin;
	  int p;
	  for (p = 1023; p > 512; p--)
	    {
	      sock = socket(AF_INET, SOCK_STREAM, 0);
	      if (sock < 0)
		fatal("socket: %.100s", strerror(errno));
	      memset(&sin, 0, sizeof(sin));
	      sin.sin_family = AF_INET;
	      sin.sin_addr.s_addr = INADDR_ANY;
	      sin.sin_port = htons(p);
	      if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) >= 0)
		break;
	      if (errno == EADDRINUSE)
		{
		  close(sock);
		  continue;
		}
	      fatal("bind: %.100s", strerror(errno));
	    }
	  debug("Allocated local port %d.", p);
	}
      else
	{ 
	  /* Just create an ordinary socket on arbitrary port. */
	  sock = socket(AF_INET, SOCK_STREAM, 0);
	  if (sock < 0)
	    fatal("socket: %.100s", strerror(errno));
	}

      /* Try to parse the host name as a numeric inet address. */
      memset(&hostaddr, 0, sizeof(hostaddr));
      hostaddr.sin_family = AF_INET;
      hostaddr.sin_port = htons(port);
#ifdef BROKEN_INET_ADDR
      hostaddr.sin_addr.s_addr = inet_network(host);
#else /* BROKEN_INET_ADDR */
      hostaddr.sin_addr.s_addr = inet_addr(host);
#endif /* BROKEN_INET_ADDR */
      if ((hostaddr.sin_addr.s_addr & 0xffffffff) != 0xffffffff)
	{ 
	  /* Valid numeric IP address */
	  debug("Connecting to %.100s port %d.", 
		inet_ntoa(hostaddr.sin_addr), port);
      
	  /* Connect to the host. */
	  if (connect(sock, (struct sockaddr *)&hostaddr, sizeof(hostaddr))
	      >= 0)
	    break;
	  debug("connect: %.100s", strerror(errno));
	}
      else
	{ 
	  /* Not a valid numeric inet address. */
	  /* Map host name to an address. */
	  if (!hp)
	    hp = gethostbyname(host);
	  if (!hp)
	    fatal("Bad host name: %.100s", host);
	  if (!hp->h_addr_list[0])
	    fatal("Host does not have an IP address: %.100s", host);

	  /* Loop through addresses for this host, and try each one in
	     sequence until the connection succeeds. */
	  for (i = 0; hp->h_addr_list[i]; i++)
	    {
	      hostaddr.sin_family = hp->h_addrtype;
	      memcpy(&hostaddr.sin_addr, hp->h_addr_list[0], 
		     sizeof(hostaddr.sin_addr));
	      debug("Connecting to %.200s [%.100s] port %d.",
		    host, inet_ntoa(hostaddr.sin_addr), port);
	      /* Connect to the host. */
	      if (connect(sock, (struct sockaddr *)&hostaddr, 
			  sizeof(hostaddr)) >= 0)
		break;
	      debug("connect: %.100s", strerror(errno));
	    }
	  if (hp->h_addr_list[i])
	    break; /* Successful connection. */
	}
      /* Failed to connect the socket.  Destroy the socket. */
      shutdown(sock, 2);
      close(sock);

      /* Sleep a moment before retrying. */
      sleep(1);
    }
  /* Return failure if we didn't get a successful connection. */
  if (attempt >= MAX_CONNECTION_ATTEMPTS)
    return -1;

  debug("Connection established.");

  /* Set socket options.  We would like the socket to disappear as soon as
     it has been closed for whatever reason. */
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
#ifdef TCP_NODELAY
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
#endif /* TCP_NODELAY */
#ifdef SO_LINGER
  linger.l_onoff = 0;
  linger.l_linger = 0;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
#endif /* SO_LINGER */

  return sock;
}

/* Checks if the user has an authentication agent, and if so, tries to
   authenticate using the agent. */

int try_agent_authentication()
{
  int status, type, bits;
  MP_INT e, n, challenge;
  char *comment;
  AuthenticationConnection *auth;
  unsigned char response[16];
  unsigned int i;

  /* Get connection to the agent. */
  auth = ssh_get_authentication_connection();
  if (!auth)
    return 0;
  
  mpz_init(&e);
  mpz_init(&n);
  mpz_init(&challenge);
  
  /* Loop through identities served by the agent. */
  for (status = ssh_get_first_identity(auth, &bits, &e, &n, &comment);
       status;
       status = ssh_get_next_identity(auth, &bits, &e, &n, &comment))
    {
      /* Try this identity. */
      debug("Trying RSA authentication via agent with '%.100s'", comment);
      xfree(comment);
      
      /* Tell the server that we are willing to authenticate using this key. */
      packet_start(SSH_CMSG_AUTH_RSA);
      packet_put_mp_int(&n);
      packet_send();
      packet_write_wait();
      
      /* Wait for server's response. */
      type = packet_read();

      /* The server sends failure if it doesn\'t like our key or does not
	 support RSA authentication. */
      if (type == SSH_SMSG_FAILURE)
	{
	  debug("Server refused our key.");
	  continue;
	}

      /* Otherwise it should have sent a challenge. */
      if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
	packet_disconnect("Protocol error during RSA authentication: %d", 
			  type);

      packet_get_mp_int(&challenge);

      debug("Received RSA challenge from server.");

      /* Ask the agent to decrypt the challenge. */
      if (!ssh_decrypt_challenge(auth, bits, &e, &n, &challenge, 
				 session_id, remote_protocol_1_1, 
				 response))
	{
	  /* The agent failed to authenticate this identifier although it
	     advertised it supports this.  Just return a wrong value. */
	  log("Authentication agent failed to decrypt challenge.");
	  memset(response, 0, sizeof(response));
	}

      debug("Sending response to RSA challenge.");

      /* Send the decrypted challenge back to the server. */
      packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
      for (i = 0; i < 16; i++)
	packet_put_char(response[i]);
      packet_send();
      packet_write_wait();
  
      /* Wait for response from the server. */
      type = packet_read();

      /* The server returns success if it accepted the authentication. */
      if (type == SSH_SMSG_SUCCESS)
	{
	  debug("RSA authentication accepted by server.");
	  mpz_clear(&e);
	  mpz_clear(&n);
	  mpz_clear(&challenge);
	  return 1;
	}

      /* Otherwise it should return failure. */
      if (type != SSH_SMSG_FAILURE)
	packet_disconnect("Protocol error waiting RSA auth response: %d", 
			  type);
    }

  mpz_clear(&e);
  mpz_clear(&n);
  mpz_clear(&challenge);

  debug("RSA authentication using agent refused.");
  return 0;
}

/* Computes the proper response to a RSA challenge, and sends the response to
   the server. */

void respond_to_rsa_challenge(MP_INT *challenge, RSAPrivateKey *prv)
{
  unsigned char buf[32], response[16];
  struct MD5Context md;
  int i;

  /* Decrypt the challenge using the private key. */
  rsa_private_decrypt(challenge, challenge, prv);

  /* Compute the response. */
  if (remote_protocol_1_1)
    {
      /* The response is MD5 of decrypted challenge plus session id. */
      mp_linearize_msb_first(buf, 32, challenge);
      MD5Init(&md);
      MD5Update(&md, buf, 32);
      MD5Update(&md, session_id, 16);
      MD5Final(response, &md);
    }
  else
    { /* XXX remove this compatibility code later */
      /* The challenge used to be interpreted with the first byte in lsb
	 (againt the spec). */
      /* Convert the decrypted data into a 32 byte buffer. */
      MP_INT aux;
      mpz_init(&aux);
      for (i = 0; i < 32; i++)
	{
	  mpz_mod_2exp(&aux, challenge, 8);
	  buf[i] = mpz_get_ui(&aux);
	  mpz_div_2exp(challenge, challenge, 8);
	}
      mpz_clear(&aux);
  
      /* Compute the MD5 of the resulting buffer.  The purpose of computing 
	 MD5 is to prevent chosen plaintext attack. */
      MD5Init(&md);
      MD5Update(&md, buf, 32);
      MD5Final(response, &md);
    }
  
  debug("Sending response to host key RSA challenge.");

  /* Send the response back to the server. */
  packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
  for (i = 0; i < 16; i++)
    packet_put_char(response[i]);
  packet_send();
  packet_write_wait();
  
  memset(buf, 0, sizeof(buf));
  memset(response, 0, sizeof(response));
  memset(&md, 0, sizeof(md));
}

/* Checks if the user has authentication file, and if so, tries to authenticate
   the user using it. */

int try_rsa_authentication(struct passwd *pw, const char *authfile)
{
  MP_INT challenge;
  RSAPrivateKey private_key;
  RSAPublicKey public_key;
  char *passphrase, *comment;
  int type, i;

  /* Try to load identification for the authentication key. */
  if (!load_public_key(authfile, &public_key, &comment))
    return 0; /* Could not load it.  Fail. */

  debug("Trying RSA authentication with key '%.100s'", comment);

  /* Tell the server that we are willing to authenticate using this key. */
  packet_start(SSH_CMSG_AUTH_RSA);
  packet_put_mp_int(&public_key.n);
  packet_send();
  packet_write_wait();

  /* We no longer need the public key. */
  rsa_clear_public_key(&public_key);
  
  /* Wait for server's response. */
  type = packet_read();

  /* The server responds with failure if it doesn\'t like our key or doesn\'t
     support RSA authentication. */
  if (type == SSH_SMSG_FAILURE)
    {
      debug("Server refused our key.");
      xfree(comment);
      return 0; /* Server refuses to authenticate with this key. */
    }

  /* Otherwise, the server should respond with a challenge. */
  if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
    packet_disconnect("Protocol error during RSA authentication: %d", type);

  /* Get the challenge from the packet. */
  mpz_init(&challenge);
  packet_get_mp_int(&challenge);

  debug("Received RSA challenge from server.");

  /* Load the private key.  Try first with empty passphrase; if it fails, 
     ask for a passphrase. */
  if (!load_private_key(authfile, "", &private_key, NULL))
    {
      char buf[300];
      /* Request passphrase from the user.  We read from /dev/tty to make
         this work even if stdin has been redirected. */
      sprintf(buf, "Enter passphrase for RSA key '%.100s': ", comment);
      passphrase = read_passphrase(buf, 0);
      
      /* Load the authentication file using the pasphrase. */
      if (!load_private_key(authfile, passphrase, &private_key, NULL))
	{
	  memset(passphrase, 0, strlen(passphrase));
	  xfree(passphrase);
	  error("Bad passphrase.");

	  /* Send a dummy response packet to avoid protocol error. */
	  packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
	  for (i = 0; i < 16; i++)
	    packet_put_char(0);
	  packet_send();
	  packet_write_wait();

	  /* Expect the server to reject it... */
	  packet_read_expect(SSH_SMSG_FAILURE);
	  xfree(comment);
	  return 0;
	}

      /* Destroy the passphrase. */
      memset(passphrase, 0, strlen(passphrase));
      xfree(passphrase);
    }
  
  /* We no longer need the comment. */
  xfree(comment);

  /* Compute and send a response to the challenge. */
  respond_to_rsa_challenge(&challenge, &private_key);
  
  /* Destroy the private key. */
  rsa_clear_private_key(&private_key);

  /* We no longer need the challenge. */
  mpz_clear(&challenge);
  
  /* Wait for response from the server. */
  type = packet_read();
  if (type == SSH_SMSG_SUCCESS)
    {
      debug("RSA authentication accepted by server.");
      return 1;
    }
  if (type != SSH_SMSG_FAILURE)
    packet_disconnect("Protocol error waiting RSA auth response: %d", type);
  debug("RSA authentication refused.");
  return 0;
}

/* Tries to authenticate the user using combined rhosts or /etc/hosts.equiv
   authentication and RSA host authentication. */

int try_rhosts_rsa_authentication(const char *local_user, 
				  RSAPrivateKey *host_key)
{
  int type;
  MP_INT challenge;

  debug("Trying rhosts or /etc/hosts.equiv with RSA host authentication.");

  /* Tell the server that we are willing to authenticate using this key. */
  packet_start(SSH_CMSG_AUTH_RHOSTS_RSA);
  packet_put_string(local_user, strlen(local_user));
  packet_put_int(host_key->bits);
  packet_put_mp_int(&host_key->e);
  packet_put_mp_int(&host_key->n);
  packet_send();
  packet_write_wait();

  /* Wait for server's response. */
  type = packet_read();

  /* The server responds with failure if it doesn't admit our .rhosts
     authentication or doesn't know our host key. */
  if (type == SSH_SMSG_FAILURE)
    {
      debug("Server refused our rhosts authentication or host key.");
      return 0; /* Server refuses to authenticate us with this method. */
    }

  /* Otherwise, the server should respond with a challenge. */
  if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
    packet_disconnect("Protocol error during RSA authentication: %d", type);

  /* Get the challenge from the packet. */
  mpz_init(&challenge);
  packet_get_mp_int(&challenge);

  debug("Received RSA challenge for host key from server.");

  /* Compute a response to the challenge. */
  respond_to_rsa_challenge(&challenge, host_key);

  /* We no longer need the challenge. */
  mpz_clear(&challenge);
  
  /* Wait for response from the server. */
  type = packet_read();
  if (type == SSH_SMSG_SUCCESS)
    {
      debug("Rhosts or /etc/hosts.equiv with RSA host authentication accepted by server.");
      return 1;
    }
  if (type != SSH_SMSG_FAILURE)
    packet_disconnect("Protocol error waiting RSA auth response: %d", type);
  debug("Rhosts or /etc/hosts.equiv with RSA host authentication refused.");
  return 0;
}

/* Starts a dialog with the server, and authenticates the current user on the
   server.  This does not need any extra privileges.  The basic connection
   to the server must already have been established before this is called. 
   User is the remote user; if it is NULL, the current local user name will
   be used.  Anonymous indicates that no rhosts authentication will be used.
   If login fails, this function prints an error and never returns. 
   This function does not require super-user privileges. */

void ssh_login(RandomState *state, int host_key_valid, 
	       RSAPrivateKey *own_host_key,
	       int sock, const char *orighost, const char *user, 
	       unsigned int num_identity_files, char **identity_files, 
	       int rhosts_authentication, int rhosts_rsa_authentication,
	       int rsa_authentication,
	       int password_authentication, int cipher_type,
	       const char *system_hostfile, const char *user_hostfile,
	       uid_t original_real_uid)
{
  int i, type, remote_major, remote_minor;
  char buf[1024]; /* Must not be larger than remote_version. */
  char remote_version[1024]; /* Must be at least as big as buf. */
  char *password;
  struct passwd *pw;
  MP_INT key;
  RSAPublicKey host_key;
  RSAPublicKey public_key;
  unsigned char session_key[SSH_SESSION_KEY_LENGTH];
  const char *server_user, *local_user;
  char *cp, *host;
  struct stat st;
  unsigned char check_bytes[8];
  unsigned int supported_ciphers, supported_authentications, protocol_flags;
  HostStatus host_status;

  /* Convert the user-supplied hostname into all lowercase. */
  host = xstrdup(orighost);
  for (cp = host; *cp; cp++)
    if (isupper(*cp))
      *cp = tolower(*cp);

  /* Read other side\'s version identification. */
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      if (read(sock, &buf[i], 1) != 1)
	fatal("read: %.100s", strerror(errno));
      if (buf[i] == '\r')
	{
	  buf[i] = '\n';
	  buf[i + 1] = 0;
	  break;
	}
      if (buf[i] == '\n')
	{
	  buf[i + 1] = 0;
	  break;
	}
    }
  buf[sizeof(buf) - 1] = 0;
  
  /* Check that the versions match.  In future this might accept several
     versions and set appropriate flags to handle them. */
  if (sscanf(buf, "SSH-%d.%d-%[^\n]\n", &remote_major, &remote_minor, 
	     remote_version) != 3)
    fatal("Bad remote protocol version identification: '%.100s'", buf);
  debug("Remote protocol version %d.%d, remote software version %.100s",
	remote_major, remote_minor, remote_version);
#if 0
  /* Removed for now, to permit compatibility with latter versions.  The server
     will reject our version and disconnect if it doesn't support it. */
  if (remote_major != PROTOCOL_MAJOR)
    fatal("Protocol major versions differ: %d vs. %d",
	  PROTOCOL_MAJOR, remote_major);
#endif

  /* Check if remote side has protocol version >= 1.1. XXX remove this later.*/
  remote_protocol_1_1 = (remote_major >= 1 && remote_minor >= 1);
  if (!remote_protocol_1_1)
    {
      log("Warning: Remote machine has old SSH software version.");
      log("Warning: Installing a newer version is recommended.");
    }

  /* Send our own protocol version identification. */
  sprintf(buf, "SSH-%d.%d-%.100s\n", 
	  PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
  if (write(sock, buf, strlen(buf)) != strlen(buf))
    fatal("write: %.100s", strerror(errno));

  /* The minor version is currently not used for anything but
     might be used to enable certain features in future. */

  /* Set the socket into non-blocking mode. */
#ifdef O_NONBLOCK
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
    error("fcntl O_NONBLOCK: %.100s", strerror(errno));
#else /* O_NONBLOCK */  
  if (fcntl(sock, F_SETFL, O_NDELAY) < 0)
    error("fcntl O_NDELAY: %.100s", strerror(errno));
#endif /* O_NONBLOCK */

  /* Get local user name.  Use it as server user if no user name
     was given. */
  pw = getpwuid(original_real_uid);
  if (!pw)
    fatal("User id %d not found from user database.", original_real_uid);
  local_user = xstrdup(pw->pw_name);
  server_user = user ? user : local_user;

  /* Initialize the connection in the packet protocol module. */
  packet_set_connection(sock, state);

  debug("Waiting for server public key.");

  /* Wait for a public key packet from the server. */
  packet_read_expect(SSH_SMSG_PUBLIC_KEY);

  /* Get check bytes from the packet. */
  for (i = 0; i < 8; i++)
    check_bytes[i] = packet_get_char();

  /* Get the public key. */
  public_key.bits = packet_get_int();
  mpz_init(&public_key.e);
  packet_get_mp_int(&public_key.e);
  mpz_init(&public_key.n);
  packet_get_mp_int(&public_key.n);

  /* Get the host key. */
  host_key.bits = packet_get_int();
  mpz_init(&host_key.e);
  packet_get_mp_int(&host_key.e);
  mpz_init(&host_key.n);
  packet_get_mp_int(&host_key.n);

  /* Get protocol flags. */
  protocol_flags = packet_get_int();
  packet_set_protocol_flags(protocol_flags);

  /* Get supported cipher types. */
  supported_ciphers = packet_get_int();

  /* Get supported authentication types. */
  supported_authentications = packet_get_int();

  debug("Received server public key (%d bits) and host key (%d bits).", 
	public_key.bits, host_key.bits);

  /* Compute the session id. */
  compute_session_id(session_id, check_bytes, host_key.bits, &host_key.n, 
		     public_key.bits, &public_key.n);

  /* Check if the host key is present in the user\'s list of known hosts
     or in the systemwide list. */
  host_status = check_host_in_hostfile(user_hostfile, host, host_key.bits, 
				       &host_key.e, &host_key.n);
  if (host_status == HOST_NEW)
    host_status = check_host_in_hostfile(system_hostfile, host, 
					 host_key.bits, &host_key.e, 
					 &host_key.n);

  /* Force accepting of the host key for localhost and 127.0.0.1.
     The problem is that if the home directory is NFS-mounted to multiple
     machines, localhost will refer to a different machine in each of them,
     and the user will get bogus HOST_CHANGED warnings.  This essentially
     disables host authentication for localhost; however, this is probably
     not a real problem. */
  if (strcmp(host, "localhost") == 0 ||
      strcmp(host, "127.0.0.1") == 0)
    {
      debug("Forcing accepting of host key for localhost.");
      host_status = HOST_OK;
    }

  switch (host_status)
    {
    case HOST_OK:
      /* The host is known and the key matches. */
      debug("Host '%.200s' is known and matches the host key.", host);
      break;
    case HOST_NEW:
      /* The host is new. */
      if (!add_host_to_hostfile(user_hostfile, host, host_key.bits, 
				&host_key.e, &host_key.n))
	log("Failed to add the host to the list of known hosts (%.500s).", 
	    user_hostfile);
      else
	log("Host '%.200s' added to the list of known hosts.", host);
      break;
    case HOST_CHANGED:
      /* The host key has changed. */
      error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
      error("@       WARNING: HOST IDENTIFICATION HAS CHANGED!         @");
      error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
      error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
      error("Someone could be eavesdropping on you right now!");
      error("It is also possible that the host key has just been changed.");
      error("Please contact your system administrator.");
      error("Add correct host key in %s to get rid of this message.", 
	    user_hostfile);
      error("Password authentication is disabled to avoid trojan horses.");
      password_authentication = 0;
      /* XXX Should permit the user to change to use the new id.  This could
         be done by converting the host key to an identifying sentence, tell
	 that the host identifies itself by that sentence, and ask the user
	 if he/she whishes to accept the authentication. */
      break;
    }

  /* Generate a session key. */
  
  /* Initialize the random number generator. */
  sprintf(buf, "%.500s/%.200s", pw->pw_dir, SSH_CLIENT_SEEDFILE);
  if (stat(buf, &st) < 0)
    log("Creating random seed file ~/%.900s.  This may take a while.", 
	SSH_CLIENT_SEEDFILE);
  else
    debug("Initializing random; seed file %.900s", buf);
  random_initialize(state, buf);
  
  /* Generate an encryption key for the session.   The key is a 256 bit
     random number, interpreted as a 32-byte key, with the least significant
     8 bits being the first byte of the key. */
  for (i = 0; i < 32; i++)
    session_key[i] = random_get_byte(state);

  /* Save the new random state. */
  random_save(state, buf);
  random_stir(state); /* This is supposed to be irreversible. */

  if (remote_protocol_1_1)
    {
      /* According to the protocol spec, the first byte of the session key is
	 the highest byte of the integer.  The session key is xored with the
	 first 16 bytes of the session id. */
      mpz_init_set_ui(&key, 0);
      for (i = 0; i < SSH_SESSION_KEY_LENGTH; i++)
	{
	  mpz_mul_2exp(&key, &key, 8);
	  if (i < 16)
	    mpz_add_ui(&key, &key, session_key[i] ^ session_id[i]);
	  else
	    mpz_add_ui(&key, &key, session_key[i]);
	}
    }
  else
    { /* XXX remove this compatibility code later. */
      /* In the old version, the session key was stored in the integer 
	 with the first byte in the lowermost bits of the integer (i.e, lsb
	 first).  Additionally, there was no xoring. */
      mpz_init_set_ui(&key, 0);
      for (i = 0; i < SSH_SESSION_KEY_LENGTH; i++)
	{
	  mpz_mul_2exp(&key, &key, 8);
	  mpz_add_ui(&key, &key, session_key[SSH_SESSION_KEY_LENGTH - i - 1]);
	}
    }

  /* Encrypt the integer using the public key and host key of the server
     (key with smaller modulus first). */
  if (mpz_cmp(&public_key.n, &host_key.n) < 0)
    {
      /* Public key has smaller modulus. */
      assert(host_key.bits >= public_key.bits + SSH_KEY_BITS_RESERVED);

      rsa_public_encrypt(&key, &key, &public_key, state);
      rsa_public_encrypt(&key, &key, &host_key, state);
    }
  else
    {
      /* Host key has smaller modulus (or they are equal). */
      assert(public_key.bits >= host_key.bits + SSH_KEY_BITS_RESERVED);

      rsa_public_encrypt(&key, &key, &host_key, state);
      rsa_public_encrypt(&key, &key, &public_key, state);
    }

  if (cipher_type == SSH_CIPHER_NOT_SET)
    if (cipher_mask() & supported_ciphers & (1 << SSH_CIPHER_IDEA))
      cipher_type = SSH_CIPHER_IDEA;
    else
      {
	debug("IDEA not supported, using %.100s instead.",
	      cipher_name(SSH_FALLBACK_CIPHER));
	cipher_type = SSH_FALLBACK_CIPHER;
      }

  /* Check that the selected cipher is supported. */
  if (!(supported_ciphers & (1 << cipher_type)))
    fatal("Selected cipher type %.100s not supported by server.", 
	  cipher_name(cipher_type));

  debug("Encryption type: %.100s", cipher_name(cipher_type));

  /* Send the encrypted session key to the server. */
  packet_start(SSH_CMSG_SESSION_KEY);
  packet_put_char(cipher_type);

  /* Send the check bytes back to the server. */
  for (i = 0; i < 8; i++)
    packet_put_char(check_bytes[i]);

  /* Send the encrypted encryption key. */
  packet_put_mp_int(&key);

  /* Send protocol flags. */
  packet_put_int(0);

  /* Send the packet now. */
  packet_send();
  packet_write_wait();

  /* Destroy the session key integer and the public keys since we no longer
     need them. */
  mpz_clear(&key);
  rsa_clear_public_key(&public_key);
  rsa_clear_public_key(&host_key);

  debug("Sent encrypted session key.");
  
  /* Set the encryption key. */
  packet_set_encryption_key(session_key, SSH_SESSION_KEY_LENGTH, 
			    cipher_type, 1);

  /* We will no longer need the session key here.  Destroy any extra copies. */
  memset(session_key, 0, sizeof(session_key));

  /* Expect a success message from the server.  Note that this message will
     be received in encrypted form. */
  packet_read_expect(SSH_SMSG_SUCCESS);

  debug("Received encrypted confirmation.");

  /* Send the name of the user to log in as on the server. */
  packet_start(SSH_CMSG_USER);
  packet_put_string(server_user, strlen(server_user));
  packet_send();
  packet_write_wait();

  /* The server should respond with success if no authentication is needed
     (the user has no password).  Otherwise the server responds with 
     failure. */
  type = packet_read();
  if (type == SSH_SMSG_SUCCESS)
    return;  /* Connection was accepted without authentication. */
  if (type != SSH_SMSG_FAILURE)
    packet_disconnect("Protocol error: got %d in response to SSH_CMSG_USER",
		      type);

  /* Use rhosts authentication if running in privileged socket and we do not
     wish to remain anonymous. */
  if ((supported_authentications & (1 << SSH_AUTH_RHOSTS)) && 
      rhosts_authentication)
    {
      debug("Trying rhosts authentication.");
      packet_start(SSH_CMSG_AUTH_RHOSTS);
      packet_put_string(local_user, strlen(local_user));
      packet_send();
      packet_write_wait();

      /* The server should respond with success or failure. */
      type = packet_read();
      if (type == SSH_SMSG_SUCCESS)
	return; /* Successful connection. */
      if (type != SSH_SMSG_FAILURE)
	packet_disconnect("Protocol error: got %d in response to rhosts auth",
			  type);
    }

  /* Try .rhosts or /etc/hosts.equiv authentication with RSA host 
     authentication. */
  if ((supported_authentications & (1 << SSH_AUTH_RHOSTS_RSA)) &&
      rhosts_rsa_authentication && host_key_valid)
    {
      if (try_rhosts_rsa_authentication(local_user, own_host_key))
	return; /* Successful authentication. */
    }

  /* Try RSA authentication if the server supports it. */
  if ((supported_authentications & (1 << SSH_AUTH_RSA)) &&
      rsa_authentication)
    {
      /* Try RSA authentication using the authentication agent.  The agent
         is tried first because no passphrase is needed for it, whereas
	 identity files may require passphrases. */
      if (try_agent_authentication())
	return; /* Successful connection. */

      /* Try RSA authentication for each identity. */
      for (i = 0; i < num_identity_files; i++)
	if (try_rsa_authentication(pw, identity_files[i]))
	  return; /* Successful connection. */
    }
  
  /* Try password authentication if the server supports it. */
  if ((supported_authentications & (1 << SSH_AUTH_PASSWORD)) &&
      password_authentication)
    {
      debug("Doing password authentication.");
      if (cipher_type == SSH_CIPHER_NONE)
	log("WARNING: Encryption is disabled! Password will be transmitted in plain text.");
      password = read_passphrase("Password: ", 0);
      packet_start(SSH_CMSG_AUTH_PASSWORD);
      packet_put_string(password, strlen(password));
      memset(password, 0, strlen(password));
      xfree(password);
      packet_send();
      packet_write_wait();
  
      type = packet_read();
      if (type == SSH_SMSG_SUCCESS)
	return; /* Successful connection. */
      if (type != SSH_SMSG_FAILURE)
	packet_disconnect("Protocol error: got %d in response to passwd auth",
			  type);
    }

  /* All authentication methods have failed.  Exit with an error message. */
  fatal("Permission denied.");
  /*NOTREACHED*/
}
