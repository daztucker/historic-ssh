/*

ssh-agent.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Mar 29 03:46:59 1995 ylo

The authentication agent program.

*/

/*
 * $Id: ssh-agent.c,v 1.18 1997/04/17 04:15:11 kivinen Exp $
 * $Log: ssh-agent.c,v $
 * Revision 1.18  1997/04/17 04:15:11  kivinen
 * 	Removed some extra variables. Removed some warnings.
 * 	Added check to socket closing that it is really opened.
 * 	Added xstrdups to putenv calls.
 *
 * Revision 1.17  1997/04/05 21:58:15  kivinen
 * 	Fixed agent option parsing. Added -- option support, patch from
 * 	Charles M. Hannum <mycroft@gnu.ai.mit.edu>.
 * 	Added closing of agent socket in parent, patch from Charles M.
 * 	Hannum <mycroft@gnu.ai.mit.edu>.
 * 	Added check for existance of O_NOCTTY (patch from
 * 	KOJIMA Hajime <kjm@rins.ryukoku.ac.jp>).
 * 	Added setting of SSH_AGENT_PID when running command too.
 *
 * Revision 1.16  1997/03/19 17:39:36  kivinen
 * 	Added -c (csh style shell) and -s (/bin/sh style shell)
 * 	options.
 * 	Fixed /bin/sh command syntax so it will print FOO=1; export
 * 	FOO; instead of export FOO=1, which some shells doesn't
 * 	understand.
 *
 * Revision 1.15  1996/11/24 08:27:33  kivinen
 * 	Added new mode for ssh-agent. If no command is given fork to
 * 	background and print commands that can be executed in users
 * 	shell that will set SSH_AUTHENTICATION_SOCKET and
 * 	SSH_AGENT_PID.
 *
 * Revision 1.14  1996/11/19 12:09:00  kivinen
 * 	Fixed check when directory needs to be created.
 *
 * Revision 1.13  1996/10/29 22:43:55  kivinen
 * 	log -> log_msg. Removed unused sockaddr_in sin.
 * 	Do not define SSH_AUTHENTICATION_SOCKET environment variable
 * 	if the agent could not be started.
 *
 * Revision 1.12  1996/10/29 12:34:29  ttsalo
 * 	Agent's behaviour improved: socket is created and listened to
 * 	before forking, and if creation fails, parent still executes
 * 	the specified command (without forking the child).
 *
 * Revision 1.11  1996/10/21 16:17:28  ttsalo
 *       Implemented direct socket handling in ssh-agent
 *
 * Revision 1.10  1996/10/20 16:19:34  ttsalo
 *      Added global variable 'original_real_uid' and it's initialization
 *
 * Revision 1.9  1996/10/12 22:19:32  ttsalo
 * 	Return value of mkdir is now checked.
 *
 * Revision 1.8  1996/09/27 14:01:33  ttsalo
 * 	Use AF_UNIX_SIZE(sunaddr) instead of sizeof(sunaddr)
 *
 * Revision 1.7  1996/09/11 17:56:52  kivinen
 * 	Changed limit of messages from 256 kB to 30 kB.
 * 	Added check that getpwuid succeeds.
 *
 * Revision 1.6  1996/09/04 12:41:51  ttsalo
 * 	Minor fixes
 *
 * Revision 1.5  1996/08/29 14:51:26  ttsalo
 * 	Agent-socket directory handling implemented
 *
 * Revision 1.4  1996/08/21 20:43:55  ttsalo
 * 	Made ssh-agent use a different, more secure way of storing
 * 	it's initial socket.
 *
 * Revision 1.3  1996/05/28 12:44:52  ylo
 * 	Remove unix-domain socket if a killed by a signal.
 *
 * Revision 1.2  1996/04/26 00:24:47  ylo
 * 	Fixed memory leaks.
 * 	Fixed free -> xfree (xmalloced data).
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.6  1995/09/21  17:13:31  ylo
 * 	Support AF_UNIX_SIZE.
 *
 * Revision 1.5  1995/08/29  22:25:22  ylo
 * 	Added compatibility support for various authentication
 * 	protocol versions.
 * 	Fixed bug in deleting identity.
 * 	Added remove_all.
 * 	New file descriptor code.
 *
 * Revision 1.4  1995/08/21  23:27:31  ylo
 * 	Added support for session_id and response_type in
 * 	authentication requests.
 *
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
#include "mpaux.h"

typedef struct
{
  int fd;
  enum { AUTH_UNUSED, AUTH_SOCKET, AUTH_SOCKET_FD } type;
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

uid_t original_real_uid = 0;

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
  MP_INT pub_e, pub_n, challenge;
  Buffer msg;
  struct MD5Context md;
  unsigned char buf[32], mdbuf[16], session_id[16];
  unsigned int response_type;

  buffer_init(&msg);
  mpz_init(&pub_e);
  mpz_init(&pub_n);
  mpz_init(&challenge);
  pub_bits = buffer_get_int(&e->input);
  buffer_get_mp_int(&e->input, &pub_e);
  buffer_get_mp_int(&e->input, &pub_n);
  buffer_get_mp_int(&e->input, &challenge);
  if (buffer_len(&e->input) == 0)
    {
      /* Compatibility code for old servers. */
      memset(session_id, 0, 16);
      response_type = 0;
    }
  else
    {
      /* New code. */
      buffer_get(&e->input, (char *)session_id, 16);
      response_type = buffer_get_int(&e->input);
    }
  for (i = 0; i < num_identities; i++)
    if (pub_bits == identities[i].key.bits &&
	mpz_cmp(&pub_e, &identities[i].key.e) == 0 &&
	mpz_cmp(&pub_n, &identities[i].key.n) == 0)
      {
	/* Decrypt the challenge using the private key. */
	rsa_private_decrypt(&challenge, &challenge, &identities[i].key);

	/* Compute the desired response. */
	switch (response_type)
	  {
	  case 0: /* As of protocol 1.0 */
	    /* This response type is no longer supported. */
	    log_msg("Compatibility with ssh protocol 1.0 no longer supported.");
	    buffer_put_char(&msg, SSH_AGENT_FAILURE);
	    goto send;

	  case 1: /* As of protocol 1.1 */
	    /* The response is MD5 of decrypted challenge plus session id. */
	    mp_linearize_msb_first(buf, 32, &challenge);
	    MD5Init(&md);
	    MD5Update(&md, buf, 32);
	    MD5Update(&md, session_id, 16);
	    MD5Final(mdbuf, &md);
	    break;

	  default:
	    fatal("process_authentication_challenge: bad response_type %d", 
		  response_type);
	    break;
	  }

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
  
  /* Check if we have the key. */
  for (i = 0; i < num_identities; i++)
    if (mpz_cmp(&identities[i].key.n, &n) == 0)
      {
	/* We have this key.  Free the old key.  Since we don\'t want to leave
	   empty slots in the middle of the array, we actually free the
	   key there and copy data from the last entry. */
	rsa_clear_private_key(&identities[i].key);
	xfree(identities[i].comment);
	if (i < num_identities - 1)
	  identities[i] = identities[num_identities - 1];
	num_identities--;
	if (num_identities == 0)
	  xfree(identities);
	mpz_clear(&dummy);
	mpz_clear(&n);

	/* Send success. */
	buffer_put_int(&e->output, 1);
	buffer_put_char(&e->output, SSH_AGENT_SUCCESS);
	return;
      }
  /* We did not have the key. */
  mpz_clear(&dummy);
  mpz_clear(&n);

  /* Send failure. */
  buffer_put_int(&e->output, 1);
  buffer_put_char(&e->output, SSH_AGENT_FAILURE);
}

/* Removes all identities from the agent. */

void process_remove_all_identities(SocketEntry *e)
{
  unsigned int i;
  
  /* Loop over all identities and clear the keys. */
  for (i = 0; i < num_identities; i++)
    {
      rsa_clear_private_key(&identities[i].key);
      xfree(identities[i].comment);
    }

  /* Mark that there are no identities. */
  num_identities = 0;
  xfree(identities);
  
  /* Send success. */
  buffer_put_int(&e->output, 1);
  buffer_put_char(&e->output, SSH_AGENT_SUCCESS);
  return;
}

/* Adds an identity to the agent. */

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
	rsa_clear_private_key(k);
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
  if (msg_len > 30 * 1024)
    {
      shutdown(e->fd, 2);
      close(e->fd);
      e->type = AUTH_UNUSED;
      buffer_free(&e->input);
      buffer_free(&e->output);
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
    case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
      process_remove_all_identities(e);
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
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    error("fcntl O_NONBLOCK: %s", strerror(errno));
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  if (fcntl(fd, F_SETFL, O_NDELAY) < 0)
    error("fcntl O_NDELAY: %s", strerror(errno));
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

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
      case AUTH_SOCKET_FD:
      case AUTH_SOCKET:
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
  int len, sock;
  char buf[1024];
  struct sockaddr_un sunaddr;

  for (i = 0; i < sockets_alloc; i++)
    switch (sockets[i].type)
      {
      case AUTH_UNUSED:
	break;
      case AUTH_SOCKET:
	if (FD_ISSET(sockets[i].fd, readset))
	  {
	    len = AF_UNIX_SIZE(sunaddr);
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
		buffer_free(&sockets[i].input);
		buffer_free(&sockets[i].output);
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
		buffer_free(&sockets[i].input);
		buffer_free(&sockets[i].output);
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
char socket_dir_name[1024];
char socket_name[1024];

RETSIGTYPE check_parent_exists(int sig)
{
  if (kill(parent_pid, 0) < 0)
    {
      remove(socket_name);
      rmdir(socket_dir_name);
      /* printf("Parent has died - Authentication agent exiting.\n"); */
      exit(1);
    }
  signal(SIGALRM, check_parent_exists);
  alarm(10);
}

RETSIGTYPE remove_socket_on_signal(int sig)
{
  remove(socket_name);
  rmdir(socket_dir_name);
  /* fprintf(stderr, "Received signal %d - Auth. agent exiting.\n", sig); */
  exit(1);
}

int main(int ac, char **av)
{
  fd_set readset, writeset;
  char buf[1024];
  int sock = -1, creation_failed = 1, pid;
  struct sockaddr_un sunaddr;
  struct passwd *pw;
  struct stat st;
  int binsh = 1, erflg = 0;
  char *sh;
  
  int i;
  int ret;

  sh = getenv("SHELL");
  if (sh != NULL && strlen(sh) > 3 &&
      sh[strlen(sh)-3] == 'c')
    binsh = 0;
  
  while (ac > 1)
    {
      if (av[1][0] == '-')
	{
	  if (av[1][1] == '-' && av[1][2] == '\0')
	    {
	      av++;
	      ac--;
	      break;
	    }
	  for(i = 1; av[1][i] != '\0'; i++)
	    {
	      switch (av[1][i])
		{
		case 's': binsh = 1; break;
		case 'c': binsh = 0; break;
		default: erflg++; break;
		}
	    }
	  av++;
	  ac--;
	}
      else
	break;
    }
  if (erflg)
    {
      fprintf(stderr, "Usage: ssh-agent [-cs] [command [args...]]\n");
      exit(0);
    }

  original_real_uid = getuid();
  
  /* The agent uses SSH_AUTHENTICATION_SOCKET. */
  
  parent_pid = getpid();
  pw = getpwuid(getuid());
  if (pw == NULL)
    {
      fprintf(stderr, "Unknown user uid = %d\n", (int) getuid());
      exit(1);
    }
  
  sprintf(socket_dir_name, SSH_AGENT_SOCKET_DIR, pw->pw_name);

  /* Start setting up the socket. Do it before forking to guarantee
     that the socket exists when the parent starts executing the
     command. Also, if something fails before fork, just execute the
     command and don't bother forking the child. */
  
  /* Check that the per-user socket directory either doesn't exist
     or has good modes */
  
  ret = stat(socket_dir_name, &st);
  if (ret == -1 && errno != ENOENT)
    {
      perror("stat");
      goto fail_socket_setup;
    }
  if (ret == -1 && errno == ENOENT && mkdir(socket_dir_name, S_IRWXU) != 0)
    {
      perror("mkdir");
      goto fail_socket_setup;
    }

  /* Check the owner and permissions */
  if (stat(socket_dir_name, &st) != 0 || pw->pw_uid != st.st_uid ||
      (st.st_mode & 077) != 0)
    {
      fprintf(stderr, "Bad modes or owner for directory \'%s\'\n",
	      socket_dir_name);
      goto fail_socket_setup;
    }

  sprintf(socket_name,
	  SSH_AGENT_SOCKET_DIR"/"SSH_AGENT_SOCKET,
	  pw->pw_name, (int)getpid());

  /* Check that socket doesn't exist */
  ret = stat(socket_name, &st);
  if (ret != -1 && errno != ENOENT)
    {
      fprintf(stderr,
	      "\'%s\' already exists (ssh-agent already running?)\n",
	      socket_name);
      goto fail_socket_setup;
    }
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror("socket");
      goto fail_socket_setup;
    }
  memset(&sunaddr, 0, AF_UNIX_SIZE(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, socket_name, sizeof(sunaddr.sun_path));
  if (bind(sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr)) < 0)
    {
      perror("bind");
      close(sock);
      goto fail_socket_setup;
    }
  if (chmod(socket_name, 0700) < 0)
    {
      perror("chmod");
      close(sock);
      goto fail_socket_setup;
    }
  if (listen(sock, 5) < 0)
    {
      perror("listen");
      close(sock);
      goto fail_socket_setup;
    }
  
  /* Everything ok so far, so permit forking. */
  creation_failed = 0;
  
fail_socket_setup:
  /* If not creation_failed, fork, and have the parent execute the command.
     The child continues as the authentication agent. If creation failed,
     don't fork the child and forget the socket */
  if (!creation_failed)
    pid = fork();
  else
    pid = 1;			/* Run only parent code */
  if (pid != 0)
    {
      /* Parent - execute the given command, if given command. */

      /* Close the agent socket */
      if (sock != -1)
	close(sock);
      
      if (ac == 1)
	{			/* No command given print socket name */
	  if (creation_failed)
	    {
	      printf("echo Agent creation failed, no agent started\n");
	      exit(0);
	    }
	  
	  if (!binsh)
	    {			/* shell is *csh */
	      printf("setenv SSH_AUTHENTICATION_SOCKET %s;\n",
		     socket_name);
	      printf("setenv SSH_AGENT_PID %d;\n", pid);
	      printf("echo Agent pid %d;\n", pid);
	    }
	  else
	    {
	      printf("SSH_AUTHENTICATION_SOCKET=%s; export SSH_AUTHENTICATION_SOCKET;\n", socket_name);
	      printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", pid);
	      printf("echo Agent pid %d;\n", pid);
	    }
	  exit(0);
	}
      /* Command given run it */
      if (!creation_failed)
	{
	  sprintf(buf, "SSH_AUTHENTICATION_SOCKET=%s", socket_name);
	  putenv(xstrdup(buf));
	  sprintf(buf, "SSH_AGENT_PID=%d", pid);
	  putenv(xstrdup(buf));
	}
      execvp(av[1], av + 1);
      perror(av[1]);
      exit(1);
    }
  
  close(0);
  close(1);
  close(2);
  chdir("/");
  
  /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
  {
    int fd;
#ifdef O_NOCTTY
    fd = open("/dev/tty", O_RDWR | O_NOCTTY);
#else
    fd = open("/dev/tty", O_RDWR);
#endif
    if (fd >= 0)
      {
	(void)ioctl(fd, TIOCNOTTY, NULL);
	close(fd);
      }
  }
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
#ifdef ultrix
  setpgrp(0, 0);
#else /* ultrix */
  if (setsid() < 0)
    error("setsid: %.100s", strerror(errno));
#endif
#endif /* HAVE_SETSID */
  
  new_socket(AUTH_SOCKET, sock);
  if (ac != 1)
    {
      signal(SIGALRM, check_parent_exists);
      alarm(10);
    }
  signal(SIGHUP, remove_socket_on_signal);
  signal(SIGTERM, remove_socket_on_signal);

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
