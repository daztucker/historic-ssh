/*

ssh-agent.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Mar 29 03:46:59 1995 ylo

The authentication agent program.

*/

/*
 * $Id: ssh-agent.c,v 1.3 1995/07/26 23:29:13 ylo Exp $
 * $Log: ssh-agent.c,v $
 * Revision 1.3  1995/07/26  23:29:13  ylo
 * 	Print software version with usage message.
 *
 * Revision 1.2  1995/07/13  01:38:26  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "ssh.h"
#include "rsa.h"
#include "randoms.h"
#include "authfd.h"
#include "buffer.h"
#include "bufaux.h"
#include "xmalloc.h"
#include "packet.h"
#include "md5.h"
#include "getput.h"

typedef struct
{
  int fd;
  enum { AUTH_UNUSED, AUTH_FD, AUTH_SOCKET, AUTH_SOCKET_FD, 
    AUTH_CONNECTION } type;
  Buffer input;
  Buffer output;
} SocketEntry;

unsigned int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef struct
{
  RSAPrivateKey key;
  char *comment;
} Identity;

unsigned int num_identities = 0;
Identity *identities = NULL;

int max_fd = 0;

void process_request_identity(SocketEntry *e)
{
  Buffer msg;
  int i;

  buffer_init(&msg);
  buffer_put_char(&msg, SSH_AGENT_RSA_IDENTITIES_ANSWER);
  buffer_put_int(&msg, num_identities);
  for (i = 0; i < num_identities; i++)
    {
      buffer_put_int(&msg, identities[i].key.bits);
      buffer_put_mp_int(&msg, &identities[i].key.e);
      buffer_put_mp_int(&msg, &identities[i].key.n);
      buffer_put_string(&msg, identities[i].comment, 
			strlen(identities[i].comment));
    }
  buffer_put_int(&e->output, buffer_len(&msg));
  buffer_append(&e->output, buffer_ptr(&msg), buffer_len(&msg));
  buffer_free(&msg);
}

void process_authentication_challenge(SocketEntry *e)
{
  int i, pub_bits;
  MP_INT pub_e, pub_n, challenge, aux;
  Buffer msg;
  struct MD5Context md;
  unsigned char buf[32], mdbuf[16];

  buffer_init(&msg);
  mpz_init(&pub_e);
  mpz_init(&pub_n);
  mpz_init(&challenge);
  pub_bits = buffer_get_int(&e->input);
  buffer_get_mp_int(&e->input, &pub_e);
  buffer_get_mp_int(&e->input, &pub_n);
  buffer_get_mp_int(&e->input, &challenge);
  for (i = 0; i < num_identities; i++)
    if (pub_bits == identities[i].key.bits &&
	mpz_cmp(&pub_e, &identities[i].key.e) == 0 &&
	mpz_cmp(&pub_n, &identities[i].key.n) == 0)
      {
	/* Decrypt the challenge using the private key. */
	rsa_private_decrypt(&challenge, &challenge, &identities[i].key);

	/* Convert the decrypted data into a 32 byte buffer. */
	mpz_init(&aux);
	for (i = 0; i < 32; i++)
	  {
	    mpz_mod_2exp(&aux, &challenge, 8);
	    buf[i] = mpz_get_ui(&aux);
	    mpz_div_2exp(&challenge, &challenge, 8);
	  }
	mpz_clear(&aux);
	
	/* Compute the MD5 of the resulting buffer.  The purpose of computing 
	   MD5 is to prevent chosen plaintext attack. */
	MD5Init(&md);
	MD5Update(&md, buf, 32);
	MD5Final(mdbuf, &md);
	
	/* Send the response. */
	buffer_put_char(&msg, SSH_AGENT_RSA_RESPONSE);
	for (i = 0; i < 16; i++)
	  buffer_put_char(&msg, mdbuf[i]);

	goto send;
      }
  /* Unknown identity.  Send failure. */
  buffer_put_char(&msg, SSH_AGENT_FAILURE);
 send:
  buffer_put_int(&e->output, buffer_len(&msg));
  buffer_append(&e->output, buffer_ptr(&msg),
		buffer_len(&msg));
  buffer_free(&msg);
  mpz_clear(&pub_e);
  mpz_clear(&pub_n);
  mpz_clear(&challenge);
}

void process_remove_identity(SocketEntry *e)
{
  unsigned int bits;
  MP_INT dummy, n;
  unsigned int i;
  
  mpz_init(&dummy);
  mpz_init(&n);
  
  /* Get the key from the packet. */
  bits = buffer_get_int(&e->input);
  buffer_get_mp_int(&e->input, &dummy);
  buffer_get_mp_int(&e->input, &n);
  
  /* Check if we already have the key. */
  for (i = 0; i < num_identities; i++)
    if (mpz_cmp(&identities[i].key.n, &n) == 0)
      {
	/* We have this key.  Free the old key.  Since we don\'t want to leave
	   empty slots in the middle of the array, we actually free the
	   key there and copy data from the last entry. */
	rsa_clear_private_key(&identities[i].key);
	if (i < num_identities - 1)
	  identities[i] = identities[num_identities];
	num_identities--;
	mpz_clear(&dummy);
	mpz_clear(&n);

	/* Send success. */
	buffer_put_int(&e->output, 1);
	buffer_put_char(&e->output, SSH_AGENT_SUCCESS);
	return;
      }

  mpz_clear(&dummy);
  mpz_clear(&n);

  /* Send failure. */
  buffer_put_int(&e->output, 1);
  buffer_put_char(&e->output, SSH_AGENT_FAILURE);
}

void process_add_identity(SocketEntry *e)
{
  RSAPrivateKey *k;
  int i;

  if (num_identities == 0)
    identities = xmalloc(sizeof(Identity));
  else
    identities = xrealloc(identities, (num_identities + 1) * sizeof(Identity));
  k = &identities[num_identities].key;
  k->bits = buffer_get_int(&e->input);
  mpz_init(&k->n);
  buffer_get_mp_int(&e->input, &k->n);
  mpz_init(&k->e);
  buffer_get_mp_int(&e->input, &k->e);
  mpz_init(&k->d);
  buffer_get_mp_int(&e->input, &k->d);
  mpz_init(&k->u);
  buffer_get_mp_int(&e->input, &k->u);
  mpz_init(&k->p);
  buffer_get_mp_int(&e->input, &k->p);
  mpz_init(&k->q);
  buffer_get_mp_int(&e->input, &k->q);
  identities[num_identities].comment = buffer_get_string(&e->input, NULL);

  /* Check if we already have the key. */
  for (i = 0; i < num_identities; i++)
    if (mpz_cmp(&identities[i].key.n, &k->n) == 0)
      {
	/* We already have this key.  Clear and free the new data and
	   return success. */
	mpz_clear(&k->n);
	mpz_clear(&k->e);
	mpz_clear(&k->d);
	mpz_clear(&k->u);
	mpz_clear(&k->p);
	mpz_clear(&k->q);
	xfree(identities[num_identities].comment);

	/* Send success. */
	buffer_put_int(&e->output, 1);
	buffer_put_char(&e->output, SSH_AGENT_SUCCESS);
	return;
      }

  /* Increment the number of identities. */
  num_identities++;
  
  /* Send a success message. */
  buffer_put_int(&e->output, 1);
  buffer_put_char(&e->output, SSH_AGENT_SUCCESS);
}

void process_message(SocketEntry *e)
{
  unsigned int msg_len;
  unsigned int type;
  unsigned char *cp;
  if (buffer_len(&e->input) < 5)
    return; /* Incomplete message. */
  cp = (unsigned char *)buffer_ptr(&e->input);
  msg_len = GET_32BIT(cp);
  if (msg_len > 256 * 1024)
    {
      shutdown(e->fd, 2);
      close(e->fd);
      e->type = AUTH_UNUSED;
      return;
    }
  if (buffer_len(&e->input) < msg_len + 4)
    return;
  buffer_consume(&e->input, 4);
  type = buffer_get_char(&e->input);
  switch (type)
    {
    case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
      process_request_identity(e);
      break;
    case SSH_AGENTC_RSA_CHALLENGE:
      process_authentication_challenge(e);
      break;
    case SSH_AGENTC_ADD_RSA_IDENTITY:
      process_add_identity(e);
      break;
    case SSH_AGENTC_REMOVE_RSA_IDENTITY:
      process_remove_identity(e);
      break;
    default:
      /* Unknown message.  Respond with failure. */
      error("Unknown message %d", type);
      buffer_clear(&e->input);
      buffer_put_int(&e->output, 1);
      buffer_put_char(&e->output, SSH_AGENT_FAILURE);
      break;
    }
}

void new_socket(int type, int fd)
{
  unsigned int i, old_alloc;
#ifdef O_NONBLOCK
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    error("fcntl O_NONBLOCK: %s", strerror(errno));
#else /* O_NONBLOCK */  
  if (fcntl(fd, F_SETFL, O_NDELAY) < 0)
    error("fcntl O_NDELAY: %s", strerror(errno));
#endif /* O_NONBLOCK */

  if (fd > max_fd)
    max_fd = fd;

  for (i = 0; i < sockets_alloc; i++)
    if (sockets[i].type == AUTH_UNUSED)
      {
	sockets[i].fd = fd;
	sockets[i].type = type;
	buffer_init(&sockets[i].input);
	buffer_init(&sockets[i].output);
	return;
      }
  old_alloc = sockets_alloc;
  sockets_alloc += 10;
  if (sockets)
    sockets = xrealloc(sockets, sockets_alloc * sizeof(sockets[0]));
  else
    sockets = xmalloc(sockets_alloc * sizeof(sockets[0]));
  for (i = old_alloc; i < sockets_alloc; i++)
    sockets[i].type = AUTH_UNUSED;
  sockets[old_alloc].type = type;
  sockets[old_alloc].fd = fd;
  buffer_init(&sockets[old_alloc].input);
  buffer_init(&sockets[old_alloc].output);
}

void prepare_select(fd_set *readset, fd_set *writeset)
{
  unsigned int i;
  for (i = 0; i < sockets_alloc; i++)
    switch (sockets[i].type)
      {
      case AUTH_FD:
      case AUTH_CONNECTION:
      case AUTH_SOCKET:
      case AUTH_SOCKET_FD:
	FD_SET(sockets[i].fd, readset);
	if (buffer_len(&sockets[i].output) > 0)
	  FD_SET(sockets[i].fd, writeset);
	break;
      case AUTH_UNUSED:
	break;
      default:
	fatal("Unknown socket type %d", sockets[i].type);
	break;
      }
}

void after_select(fd_set *readset, fd_set *writeset)
{
  unsigned int i;
  int len, sock, port;
  char buf[1024];
  struct sockaddr_in sin;
  struct sockaddr_un sunaddr;

  for (i = 0; i < sockets_alloc; i++)
    switch (sockets[i].type)
      {
      case AUTH_UNUSED:
	break;
      case AUTH_FD:
	if (FD_ISSET(sockets[i].fd, readset))
	  {
	    len = recv(sockets[i].fd, buf, sizeof(buf), 0);
	    if (len <= 0)
	      { /* All instances of the other side have been closed. */
		log("Authentication agent exiting.");
		exit(0);
	      }
	  process_auth_fd_input:
	    if (len != 3 || (unsigned char)buf[0] != SSH_AUTHFD_CONNECT)
	      break; /* Incorrect message; ignore it. */
	    /* It is a connection request message. */
	    port = (unsigned char)buf[1] * 256 + (unsigned char)buf[2];
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = htonl(0x7f000001); /* localhost */
	    sin.sin_port = htons(port);
	    sock = socket(AF_INET, SOCK_STREAM, 0);
	    if (sock < 0)
	      {
		perror("socket");
		break;
	      }
	    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	      {
		perror("connecting to port requested in authfd message");
		close(sock);
		break;
	      }
	    new_socket(AUTH_CONNECTION, sock);
	  }
	break;
      case AUTH_SOCKET:
	if (FD_ISSET(sockets[i].fd, readset))
	  {
	    len = sizeof(sunaddr);
	    sock = accept(sockets[i].fd, (struct sockaddr *)&sunaddr, &len);
	    if (sock < 0)
	      {
		perror("accept from AUTH_SOCKET");
		break;
	      }
	    new_socket(AUTH_SOCKET_FD, sock);
	  }
	break;
      case AUTH_SOCKET_FD:
	if (FD_ISSET(sockets[i].fd, readset))
	  {
	    len = recv(sockets[i].fd, buf, sizeof(buf), 0);
	    if (len <= 0)
	      { /* The other side has closed the socket. */
		shutdown(sockets[i].fd, 2);
		close(sockets[i].fd);
		sockets[i].type = AUTH_UNUSED;
		break;
	      }
	    goto process_auth_fd_input;
	  }
	break;
      case AUTH_CONNECTION:
	if (buffer_len(&sockets[i].output) > 0 &&
	    FD_ISSET(sockets[i].fd, writeset))
	  {
	    len = write(sockets[i].fd, buffer_ptr(&sockets[i].output),
			buffer_len(&sockets[i].output));
	    if (len <= 0)
	      {
		shutdown(sockets[i].fd, 2);
		close(sockets[i].fd);
		sockets[i].type = AUTH_UNUSED;
		break;
	      }
	    buffer_consume(&sockets[i].output, len);
	  }
	if (FD_ISSET(sockets[i].fd, readset))
	  {
	    len = read(sockets[i].fd, buf, sizeof(buf));
	    if (len <= 0)
	      {
		shutdown(sockets[i].fd, 2);
		close(sockets[i].fd);
		sockets[i].type = AUTH_UNUSED;
		break;
	      }
	    buffer_append(&sockets[i].input, buf, len);
	    process_message(&sockets[i]);
	  }
	break;
      default:
	fatal("Unknown type %d", sockets[i].type);
      }
}

int parent_pid = -1;
char socket_name[1024];

RETSIGTYPE check_parent_exists(int sig)
{
  if (kill(parent_pid, 0) < 0)
    {
      remove(socket_name);
      /* printf("Parent has died - Authentication agent exiting.\n"); */
      exit(1);
    }
  signal(SIGALRM, check_parent_exists);
  alarm(10);
}

int main(int ac, char **av)
{
  fd_set readset, writeset;
  char buf[1024];
#ifdef AGENT_USES_SOCKET
  int sock;
  struct sockaddr_un sunaddr;
#else /* AGENT_USES_SOCKET */
  int sockets[2], dups[SSH_NUM_DUPS], i;
#endif /* AGENT_USES_SOCKET */

  if (ac < 2)
    {
      fprintf(stderr, "ssh-agent version %s\n", SSH_VERSION);
      fprintf(stderr, "Usage: %s command\n", av[0]);
      exit(1);
    }

#ifdef AGENT_USES_SOCKET
  /* The agent uses SSH_AUTHENTICATION_SOCKET. */

  parent_pid = getpid();

  sprintf(socket_name, SSH_AGENT_SOCKET, parent_pid);
  
  /* Fork, and have the parent execute the command.  The child continues as
     the authentication agent. */
  if (fork() != 0)
    { /* Parent - execute the given command. */
      sprintf(buf, "SSH_AUTHENTICATION_SOCKET=%s", socket_name);
      putenv(buf);
      execvp(av[1], av + 1);
      perror(av[1]);
      exit(1);
    }

  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror("socket");
      exit(1);
    }
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, socket_name, sizeof(sunaddr.sun_path));
  if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0)
    {
      perror("bind");
      exit(1);
    }
  if (chmod(socket_name, 0700) < 0)
    {
      perror("chmod");
      exit(1);
    }
  if (listen(sock, 5) < 0)
    {
      perror("listen");
      exit(1);
    }
  new_socket(AUTH_SOCKET, sock);
  signal(SIGALRM, check_parent_exists);
  alarm(10);

#else /* AGENT_USES_SOCKET */

  /* The agent uses SSH_AUTHENTICATION_FD. */

  /* Dup some descriptors to get the authentication fd above 10.  This is
     because some shells arbitrarily close descriptors below that. */
  for (i = 0; i < SSH_NUM_DUPS; i++)
    dups[i] = dup(0);

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
    {
      perror("socketpair");
      exit(1);
    }
  
  /* Close duped descriptors. */
  for (i = 0; i < SSH_NUM_DUPS; i++)
    close(dups[i]);

  if (fork() != 0)
    { /* Parent - execute the given command. */
      close(sockets[0]);
      sprintf(buf, "SSH_AUTHENTICATION_FD=%d", sockets[1]);
      putenv(buf);
      execvp(av[1], av + 1);
      perror(av[1]);
      exit(1);
    }
  close(sockets[1]);
  new_socket(AUTH_FD, sockets[0]);

#endif /* AGENT_USES_SOCKET */

  signal(SIGINT, SIG_IGN);
  while (1)
    {
      FD_ZERO(&readset);
      FD_ZERO(&writeset);
      prepare_select(&readset, &writeset);
      if (select(max_fd + 1, &readset, &writeset, NULL, NULL) < 0)
	{
	  if (errno == EINTR)
	    continue;
	  perror("select");
	  exit(1);
	}
      after_select(&readset, &writeset);
    }
  /*NOTREACHED*/
}

void fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}
