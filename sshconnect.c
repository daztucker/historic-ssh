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
 * $Id: sshconnect.c,v 1.15 1995/09/27 02:16:40 ylo Exp $
 * $Log: sshconnect.c,v $
 * Revision 1.15  1995/09/27  02:16:40  ylo
 * 	Eliminated compiler warning.
 *
 * Revision 1.14  1995/09/25  00:02:55  ylo
 * 	Added connection_attempts.
 * 	Added screen number forwarding.
 *
 * Revision 1.13  1995/09/22  22:23:23  ylo
 * 	Changed interface of ssh_login to use the option structure
 * 	instead of numerous individual arguments.
 *
 * Revision 1.12  1995/09/21  17:17:44  ylo
 * 	Added original_real_uid argument to ssh_connect.
 *
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
#include "userfile.h"

/* Session id for the current session. */
unsigned char session_id[16];

/* Connect to the given ssh server using a proxy command. */

int ssh_proxy_connect(const char *host, int port, uid_t original_real_uid,
		      const char *proxy_command, RandomState *random_state)
{
  Buffer command;
  const char *cp;
  char *command_string;
  int pin[2], pout[2];
  int pid;
  char portstring[100];

  /* Convert the port number into a string. */
  sprintf(portstring, "%d", port);

  /* Build the final command string in the buffer by making the appropriate
     substitutions to the given proxy command. */
  buffer_init(&command);
  for (cp = proxy_command; *cp; cp++)
    {
      if (cp[0] == '%' && cp[1] == '%')
	{
	  buffer_append(&command, "%", 1);
	  cp++;
	  continue;
	}
      if (cp[0] == '%' && cp[1] == 'h')
	{
	  buffer_append(&command, host, strlen(host));
	  cp++;
	  continue;
	}
      if (cp[0] == '%' && cp[1] == 'p')
	{
	  buffer_append(&command, portstring, strlen(portstring));
	  cp++;
	  continue;
	}
      buffer_append(&command, cp, 1);
    }
  buffer_append(&command, "\0", 1);

  /* Get the final command string. */
  command_string = buffer_ptr(&command);

  /* Create pipes for communicating with the proxy. */
  if (pipe(pin) < 0 || pipe(pout) < 0)
    fatal("Could not create pipes to communicate with the proxy: %.100s",
	  strerror(errno));

  debug("Executing proxy command: %.500s", command_string);

  /* Fork and execute the proxy command. */
  if ((pid = fork()) == 0)
    {
      char *argv[10];

      /* Child.  Permanently give up superuser privileges. */
      if (setuid(getuid()) < 0)
	fatal("setuid: %s", strerror(errno));

      /* Redirect stdin and stdout. */
      close(pin[1]);
      if (pin[0] != 0)
	{
	  if (dup2(pin[0], 0) < 0)
	    perror("dup2 stdin");
	  close(pin[0]);
	}
      close(pout[0]);
      if (dup2(pout[1], 1) < 0)
	perror("dup2 stdout");
      close(pout[1]); /* Cannot be 1 because pin allocated two descriptors. */

      /* Stderr is left as it is so that error messages get printed on
	 the user's terminal. */
      argv[0] = "/bin/sh";
      argv[1] = "-c";
      argv[2] = command_string;
      argv[3] = NULL;
      
      /* Execute the proxy command.  Note that we gave up any extra 
	 privileges above. */
      execv("/bin/sh", argv);
      perror("/bin/sh");
      exit(1);
    }
  /* Parent. */
  if (pid < 0)
    fatal("fork failed: %.100s", strerror(errno));
  
  /* Close child side of the descriptors. */
  close(pin[0]);
  close(pout[1]);

  /* Free the command name. */
  buffer_free(&command);
  
  /* Set the connection file descriptors. */
  packet_set_connection(pout[0], pin[1], random_state);

  return 1;
}

/* Creates a (possibly privileged) socket for use as the ssh connection. */

int ssh_create_socket(uid_t original_real_uid, int privileged)
{
  int sock;

  /* If we are running as root and want to connect to a privileged port,
     bind our own socket to a privileged port. */
  if (privileged)
    {
      struct sockaddr_in sin;
      int p;
      for (p = 1023; p > 512; p--)
	{
	  sock = socket(AF_INET, SOCK_STREAM, 0);
	  if (sock < 0)
	    fatal("socket: %.100s", strerror(errno));
	  
	  /* Initialize the desired sockaddr_in structure. */
	  memset(&sin, 0, sizeof(sin));
	  sin.sin_family = AF_INET;
	  sin.sin_addr.s_addr = INADDR_ANY;
	  sin.sin_port = htons(p);

	  /* Try to bind the socket to the privileged port. */
	  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) >= 0)
	    break; /* Success. */
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
      /* Just create an ordinary socket on arbitrary port.  */
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock < 0)
	fatal("socket: %.100s", strerror(errno));
    }
  return sock;
}

/* Opens a TCP/IP connection to the remote server on the given host.  If
   port is 0, the default port will be used.  If anonymous is zero,
   a privileged port will be allocated to make the connection. 
   This requires super-user privileges if anonymous is false. 
   Connection_attempts specifies the maximum number of tries (one per
   second).  If proxy_command is non-NULL, it specifies the command (with %h 
   and %p substituted for host and port, respectively) to use to contact
   the daemon. */

int ssh_connect(const char *host, int port, int connection_attempts,
		int anonymous, uid_t original_real_uid, 
		const char *proxy_command, RandomState *random_state)
{
  int sock = -1, attempt, i;
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

  /* If a proxy command is given, connect using it. */
  if (proxy_command != NULL)
    return ssh_proxy_connect(host, port, original_real_uid, proxy_command,
			     random_state);

  /* No proxy command. */

  /* No host lookup made yet. */
  hp = NULL;
  
  /* Try to connect several times.  On some machines, the first time will
     sometimes fail.  In general socket code appears to behave quite
     magically on many machines. */
  for (attempt = 0; attempt < connection_attempts; attempt++)
    {
      if (attempt > 0)
	debug("Trying again...");

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
      
	  /* Create a socket. */
	  sock = ssh_create_socket(original_real_uid, 
				   !anonymous && geteuid() == 0 && 
				     port < 1024);
      
	  /* Connect to the host. */
	  if (connect(sock, (struct sockaddr *)&hostaddr, sizeof(hostaddr))
	      >= 0)
	    {
	      /* Successful connect. */
	      break;
	    }
	  debug("connect: %.100s", strerror(errno));

	  /* Destroy the failed socket. */
	  shutdown(sock, 2);
	  close(sock);
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
	      /* Set the address to connect to. */
	      hostaddr.sin_family = hp->h_addrtype;
	      memcpy(&hostaddr.sin_addr, hp->h_addr_list[i],
		     sizeof(hostaddr.sin_addr));

	      debug("Connecting to %.200s [%.100s] port %d.",
		    host, inet_ntoa(hostaddr.sin_addr), port);

	      /* Create a socket for connecting. */
	      sock = ssh_create_socket(original_real_uid, 
				       !anonymous && geteuid() == 0 && 
				         port < 1024);

	      /* Connect to the host. */
	      if (connect(sock, (struct sockaddr *)&hostaddr, 
			  sizeof(hostaddr)) >= 0)
		{
		  /* Successful connection. */
		  break;
		}
	      debug("connect: %.100s", strerror(errno));

	      /* Close the failed socket; there appear to be some problems 
		 when reusing a socket for which connect() has already 
		 returned an error. */
	      shutdown(sock, 2);
	      close(sock);
	    }
	  if (hp->h_addr_list[i])
	    break; /* Successful connection. */
	}

      /* Sleep a moment before retrying. */
      sleep(1);
    }
  /* Return failure if we didn't get a successful connection. */
  if (attempt >= connection_attempts)
    return 0;

  debug("Connection established.");

  /* Set socket options.  We would like the socket to disappear as soon as
     it has been closed for whatever reason. */
  /* setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)); */
#ifdef TCP_NODELAY
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
#endif /* TCP_NODELAY */
#ifdef SO_LINGER
  linger.l_onoff = 1;
  linger.l_linger = 15;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
#endif /* SO_LINGER */

  /* Set the connection. */
  packet_set_connection(sock, sock, random_state);

  return 1;
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
				 session_id, 1, response))
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
  /* The response is MD5 of decrypted challenge plus session id. */
  mp_linearize_msb_first(buf, 32, challenge);
  MD5Init(&md);
  MD5Update(&md, buf, 32);
  MD5Update(&md, session_id, 16);
  MD5Final(response, &md);
  
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

int try_rsa_authentication(struct passwd *pw, const char *authfile,
			   int may_ask_passphrase)
{
  MP_INT challenge;
  RSAPrivateKey private_key;
  RSAPublicKey public_key;
  char *passphrase, *comment;
  int type, i;

  /* Try to load identification for the authentication key. */
  if (!load_public_key(pw->pw_uid, authfile, &public_key, &comment))
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
  if (!load_private_key(pw->pw_uid, authfile, "", &private_key, NULL))
    {
      char buf[300];
      /* Request passphrase from the user.  We read from /dev/tty to make
         this work even if stdin has been redirected.  If running in
	 batch mode, we just use the empty passphrase, which will fail and
	 return. */
      sprintf(buf, "Enter passphrase for RSA key '%.100s': ", comment);
      if (may_ask_passphrase)
	passphrase = read_passphrase(pw->pw_uid, buf, 0);
      else
	{
	  debug("Will not query passphrase for %.100s in batch mode.", 
		comment);
	  passphrase = xstrdup("");
	}
      
      /* Load the authentication file using the pasphrase. */
      if (!load_private_key(pw->pw_uid, authfile, passphrase, &private_key, 
			    NULL))
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

/* Waits for the server identification string, and sends our own identification
   string. */

void ssh_exchange_identification()
{
  char buf[256], remote_version[256]; /* must be same size! */
  int remote_major, remote_minor, i;
  int connection_in = packet_get_connection_in();
  int connection_out = packet_get_connection_out();

  /* Read other side\'s version identification. */
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      if (read(connection_in, &buf[i], 1) != 1)
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

  /* Check if the remote protocol version is too old. */
  if (remote_major == 1 && remote_minor == 0)
    fatal("Remote machine has too old SSH software version.");

  /* Send our own protocol version identification. */
  sprintf(buf, "SSH-%d.%d-%.100s\n", 
	  PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
  if (write(connection_out, buf, strlen(buf)) != strlen(buf))
    fatal("write: %.100s", strerror(errno));
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
	       const char *orighost, 
	       Options *options, uid_t original_real_uid)
{
  int i, type, len, f;
  char buf[1024], seedbuf[16];
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

  /* Exchange protocol version identification strings with the server. */
  ssh_exchange_identification();

  /* Put the connection into non-blocking mode. */
  packet_set_nonblocking();

  /* Get local user name.  Use it as server user if no user name
     was given. */
  pw = getpwuid(original_real_uid);
  if (!pw)
    fatal("User id %d not found from user database.", original_real_uid);
  local_user = xstrdup(pw->pw_name);
  server_user = options->user ? options->user : local_user;

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

  /* Check if the host key is present in the user's list of known hosts
     or in the systemwide list. */
  host_status = check_host_in_hostfile(original_real_uid,
				       options->user_hostfile, 
				       host, host_key.bits, 
				       &host_key.e, &host_key.n);
  if (host_status == HOST_NEW)
    host_status = check_host_in_hostfile(original_real_uid,
					 options->system_hostfile, host, 
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
      if (options->strict_host_key_checking)
	{ /* User has requested strict host key checking.  We will not
	     add the host key automatically.  The only alternative left
	     is to abort. */
	  fatal("No host key is known for %.200s and you have requested strict checking.", host);
	}
      /* If not in strict mode, add the key automatically to the local
	 known_hosts file. */
      if (!add_host_to_hostfile(original_real_uid,
				options->user_hostfile, host, host_key.bits,
				&host_key.e, &host_key.n))
	log("Failed to add the host to the list of known hosts (%.500s).", 
	    options->user_hostfile);
      else
	log("Host '%.200s' added to the list of known hosts.", host);
      break;
    case HOST_CHANGED:
      /* The host key has changed. */
      error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
      error("@       WARNING: HOST IDENTIFICATION HAS CHANGED!         @");
      error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
      error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
      error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
      error("It is also possible that the host key has just been changed.");
      error("Please contact your system administrator.");
      error("Add correct host key in %s to get rid of this message.", 
	    options->user_hostfile);

      /* If strict host key checking is in use, the user will have to edit
	 the key manually and we can only abort. */
      if (options->strict_host_key_checking)
	fatal("Host key for %.200s has changed and you have requested strict checking.", host);

      /* If strict host key checking has not been requested, allow the
	 connection but without password authentication. */
      error("Password authentication is disabled to avoid trojan horses.");
      options->password_authentication = 0;
      /* XXX Should permit the user to change to use the new id.  This could
         be done by converting the host key to an identifying sentence, tell
	 that the host identifies itself by that sentence, and ask the user
	 if he/she whishes to accept the authentication. */
      break;
    }

  /* Generate a session key. */
  
  /* Initialize the random number generator. */
  sprintf(buf, "%.500s/%.200s", pw->pw_dir, SSH_CLIENT_SEEDFILE);
  if (userfile_stat(pw->pw_uid, buf, &st) < 0)
    log("Creating random seed file ~/%.200s.  This may take a while.", 
	SSH_CLIENT_SEEDFILE);
  else
    debug("Initializing random; seed file %.900s", buf);
  random_initialize(state, pw->pw_uid, buf);

  /* Read also some random data from the systemwide random seed file to
     avoid the user being able to guess his own session key when running
     as root. */
  f = open(SSH_DAEMON_SEED_FILE, O_RDONLY);
  if (f >= 0)
    {
      len = read(f, seedbuf, sizeof(seedbuf)); /* Try to read 128 bits. */
      if (len > 0)
	{
	  random_add_noise(state, seedbuf, len);
	  random_stir(state);
	}
      close(f);
    }

  /* Generate an encryption key for the session.   The key is a 256 bit
     random number, interpreted as a 32-byte key, with the least significant
     8 bits being the first byte of the key. */
  for (i = 0; i < 32; i++)
    session_key[i] = random_get_byte(state);

  /* Save the new random state. */
  random_save(state, pw->pw_uid, buf);

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

  if (options->cipher == SSH_CIPHER_NOT_SET)
    if (cipher_mask() & supported_ciphers & (1 << SSH_CIPHER_IDEA))
      options->cipher = SSH_CIPHER_IDEA;
    else
      {
	debug("IDEA not supported, using %.100s instead.",
	      cipher_name(SSH_FALLBACK_CIPHER));
	options->cipher = SSH_FALLBACK_CIPHER;
      }

  /* Check that the selected cipher is supported. */
  if (!(supported_ciphers & (1 << options->cipher)))
    fatal("Selected cipher type %.100s not supported by server.", 
	  cipher_name(options->cipher));

  debug("Encryption type: %.100s", cipher_name(options->cipher));

  /* Send the encrypted session key to the server. */
  packet_start(SSH_CMSG_SESSION_KEY);
  packet_put_char(options->cipher);

  /* Send the check bytes back to the server. */
  for (i = 0; i < 8; i++)
    packet_put_char(check_bytes[i]);

  /* Send the encrypted encryption key. */
  packet_put_mp_int(&key);

  /* Send protocol flags. */
  packet_put_int(SSH_PROTOFLAG_SCREEN_NUMBER | SSH_PROTOFLAG_HOST_IN_FWD_OPEN);

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
			    options->cipher, 1);

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
      options->rhosts_authentication)
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
      options->rhosts_rsa_authentication && host_key_valid)
    {
      if (try_rhosts_rsa_authentication(local_user, own_host_key))
	return; /* Successful authentication. */
    }

  /* Try RSA authentication if the server supports it. */
  if ((supported_authentications & (1 << SSH_AUTH_RSA)) &&
      options->rsa_authentication)
    {
      /* Try RSA authentication using the authentication agent.  The agent
         is tried first because no passphrase is needed for it, whereas
	 identity files may require passphrases. */
      if (try_agent_authentication())
	return; /* Successful connection. */

      /* Try RSA authentication for each identity. */
      for (i = 0; i < options->num_identity_files; i++)
	if (try_rsa_authentication(pw, options->identity_files[i],
				   !options->batch_mode))
	  return; /* Successful connection. */
    }
  
  /* Try password authentication if the server supports it. */
  if ((supported_authentications & (1 << SSH_AUTH_PASSWORD)) &&
      options->password_authentication && !options->batch_mode)
    {
      debug("Doing password authentication.");
      if (options->cipher == SSH_CIPHER_NONE)
	log("WARNING: Encryption is disabled! Password will be transmitted in clear text.");
      password = read_passphrase(pw->pw_uid, "Password: ", 0);
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
