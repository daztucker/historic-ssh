/*

sshd.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 17 17:09:28 1995 ylo

This program is the ssh daemon.  It listens for connections from clients, and
performs authentication, executes use commands or shell, and forwards
information to/from the application to the user client over an encrypted
connection.  This can also handle forwarding of X11, TCP/IP, and authentication
agent connections.

*/

/*
 * $Id: sshd.c,v 1.18 1995/09/06 19:53:19 ylo Exp $
 * $Log: sshd.c,v $
 * Revision 1.18  1995/09/06  19:53:19  ylo
 * 	Fixed spelling of fascist.
 *
 * Revision 1.17  1995/09/06  16:02:40  ylo
 * 	Added /usr/bin/X11 to default DEFAULT_PATH.
 * 	Fixed inetd_flag & debug_flag together.
 * 	Fixed -i.
 *
 * Revision 1.16  1995/08/31  09:43:14  ylo
 * 	Fixed LOGNAME.
 *
 * Revision 1.15  1995/08/31  09:26:22  ylo
 * 	Copy struct pw.
 * 	Use socketpairs for communicating with the shell/command.
 * 	Use same socket for stdin and stdout. (may help rdist)
 * 	Put LOGNAME in environment.
 * 	Run xauth directly, without the shell in between.
 * 	Fixed the HPSUX kludge.
 *
 * Revision 1.14  1995/08/29  22:36:12  ylo
 * 	Added SIGHUP handling.  Added SIGTERM and SIGQUIT handling.
 * 	Permit root login if forced command.
 * 	Added DenyHosts, AllowHosts.  Added PrintMotd.
 * 	New file descriptor code.
 * 	Use HPSUX and SIGCHLD kludges only on HPUX.
 *
 * Revision 1.13  1995/08/22  14:06:11  ylo
 * 	Added /usr/local/bin in default DEFAULT_PATH.
 *
 * Revision 1.12  1995/08/21  23:33:48  ylo
 * 	Added "-f conffile" option.
 * 	Added support for the server configuration file.
 * 	Added allow/deny host code.
 * 	Added code to optionally deny root logins.
 * 	Added code to configure allowed authentication methods.
 * 	Changes to log initialization arguments.
 * 	Eliminated NO_RHOSTS_AUTHENTICATION.
 *
 * Revision 1.11  1995/08/18  22:58:06  ylo
 * 	Added support for O_NONBLOCK_BROKEN.
 * 	Added support for TTY_GROUP.
 *
 * Revision 1.10  1995/07/27  02:19:09  ylo
 * 	Tell packet_set_encryption_key that we are the server.
 *
 * 	Temporary kludge to make TCP/IP port forwarding work
 * 	properly.  This kludge will increase idle CPU usage because
 * 	sshd wakes up every 300ms.
 *
 * Revision 1.9  1995/07/27  00:41:34  ylo
 * 	If DEFAULT_PATH defined by configure, use that value.
 *
 * Revision 1.8  1995/07/26  23:21:06  ylo
 * 	Removed include version.h.  Added include mpaux.h.
 *
 * 	Print software version with -d.
 *
 * 	Added support for protocol version 1.1.  Fixes minor security
 * 	problems, and updates the protocol to match the draft RFC.
 * 	Compatibility code makes it possible to use old clients with
 * 	this server.
 *
 * Revision 1.7  1995/07/16  01:01:41  ylo
 * 	Removed hostname argument from record_logout.
 * 	Added call to pty_release.
 * 	Set tty mode depending on whether we have tty group.
 *
 * Revision 1.6  1995/07/15  22:27:04  ylo
 * 	Added printing of /etc/motd.
 *
 * Revision 1.5  1995/07/15  21:41:04  ylo
 * 	Changed the HPSUX kludge (child_has_terminated).  It caused
 * 	sshd to busy-loop if the program exited but there were open
 * 	connections.
 *
 * Revision 1.4  1995/07/14  23:37:43  ylo
 * 	Limit outgoing packet size to 512 bytes for interactive
 * 	connections.
 *
 * Revision 1.3  1995/07/13  17:33:17  ylo
 * 	Only record the pid in /etc/sshd_pid if running without the
 * 	debugging flag.
 *
 * Revision 1.2  1995/07/13  01:40:47  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include <gmp.h>
#include "xmalloc.h"
#include "rsa.h"
#include "ssh.h"
#include "pty.h"
#include "packet.h"
#include "buffer.h"
#include "cipher.h"
#include "mpaux.h"
#include "servconf.h"
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */

#ifdef _PATH_BSHELL
#define DEFAULT_SHELL		_PATH_BSHELL
#else
#define DEFAULT_SHELL		"/bin/sh"
#endif

#ifndef DEFAULT_PATH
#ifdef _PATH_USERPATH
#define DEFAULT_PATH		_PATH_USERPATH
#else
#define DEFAULT_PATH	"/bin:/usr/bin:/usr/ucb:/usr/bin/X11:/usr/local/bin"
#endif
#endif /* DEFAULT_PATH */

#ifndef O_NOCTTY
#define O_NOCTTY	0
#endif

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
char *config_file_name = SERVER_CONFIG_FILE;

/* Debug mode flag.  This can be set on the command line.  If debug
   mode is enabled, extra debugging output will be sent to the system
   log, the daemon will not go to background, and will exit after processing
   the first connection. */
int debug_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
int inetd_flag = 0;

/* This flag is set to true if the remote protocol version is 1.1 or higher. */
int remote_protocol_1_1 = 0;

/* Saved value of argv[0]. */
char *av0;

/* Saved arguments to main(). */
char **saved_argv;

/* This is set to the socket that the server is listening; this is used in
   the SIGHUP signal handler. */
int listen_sock;

/* Flags set in auth-rsa from authorized_keys flags.  These are set in
  auth-rsa.c. */
int no_port_forwarding_flag = 0;
int no_agent_forwarding_flag = 0;
int no_x11_forwarding_flag = 0;
int no_pty_flag = 0;
char *forced_command = NULL;  /* RSA authentication "command=" option. */

/* Session id for the current session. */
unsigned char session_id[16];

/* Any really sensitive data in the application is contained in this structure.
   The idea is that this structure could be locked into memory so that the
   pages do not get written into swap.  However, there are some problems.
   The private key contains MP_INTs, and we do not (in principle) have
   access to the internals of them, and locking just the structure is not
   very useful.  Currently, memory locking is not implemented. */
struct
{
  /* Random number generator. */
  RandomState random_state;
  
  /* Private part of server key. */
  RSAPrivateKey private_key;

  /* Private part of host key. */
  RSAPrivateKey host_key;
} sensitive_data;

/* Flag indicating whether the current session key has been used.  This flag
   is set whenever the key is used, and cleared when the key is regenerated. */
int key_used = 0;

/* Public side of the server key.  This value is regenerated regularly with
   the private key. */
RSAPublicKey public_key;

/* Prototypes for various functions defined later in this file. */
void do_connection(int sock, int privileged_port);
void do_authentication(char *user, int privileged_port);
void do_authenticated(struct passwd *pw);
void do_exec_pty(const char *command, int ptyfd, int ttyfd, 
		 const char *ttyname, struct passwd *pw, const char *term,
		 const char *display, const char *auth_proto,
		 const char *auth_data);
void do_exec_no_pty(const char *command, struct passwd *pw,
		    const char *display, const char *auth_proto,
		    const char *auth_data);
void do_child(const char *command, struct passwd *pw, const char *term,
	      const char *display, const char *auth_proto,
	      const char *auth_data);
void do_session(int pid, int fdin, int fdout, int fderr);


/* Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
   the effect is to reread the configuration file (and to regenerate
   the server key). */

RETSIGTYPE sighup_handler(int sig)
{
  log("Received SIGHUP; restarting.");
  close(listen_sock);
  execv(av0, saved_argv);
  log("RESTART FAILED: av0='%s', error: %s.", av0, strerror(errno));
}

/* Generic signal handler for terminating signals in the master daemon. 
   These close the listen socket; not closing it seems to cause "Address
   already in use" problems on some machines, which is inconvenient. */

RETSIGTYPE sigterm_handler(int sig)
{
  log("Received signal %d; terminating.", sig);
  close(listen_sock);
  exit(255);
}

/* Signal handler for the alarm after the login grace period has expired. */

RETSIGTYPE grace_alarm_handler(int sig)
{
  /* Close the connection. */
  packet_close();
  
  /* Log error and exit. */
  fatal("Timeout before authentication.");
}

/* Signal handler for the key regeneration alarm.  Note that this
   alarm only occurs in the daemon waiting for connections, and it does not
   do anything with the private key or random state before forking.  Thus there
   should be no concurrency control/asynchronous execution problems. */

RETSIGTYPE key_regeneration_alarm(int sig)
{
  /* Check if we should generate a new key. */
  if (key_used)
    {
      /* This should really be done in the background. */
      log("Generating new %d bit RSA key.", options.server_key_bits);
      random_acquire_environmental_noise(&sensitive_data.random_state);
      rsa_generate_key(&sensitive_data.private_key, &public_key, 
		       &sensitive_data.random_state, options.server_key_bits);
      random_stir(&sensitive_data.random_state);
      random_save(&sensitive_data.random_state, SSH_DAEMON_SEED_FILE);
      key_used = 0;
      log("RSA key generation complete.");
    }

  /* Reschedule the alarm. */
  signal(SIGALRM, key_regeneration_alarm);
  alarm(options.key_regeneration_time);
}

/* Main program for the daemon. */

int main(int ac, char **av)
{
  extern char *optarg;
  extern int optind;
  int opt, aux, sock, newsock, i, client_port, wait_status, pid, on = 1;
  int remote_major, remote_minor;
  struct sockaddr_in sin;
  char buf[100]; /* Must not be larger than remote_version. */
  char remote_version[100]; /* Must be at least as big as buf. */
  char *comment;
  FILE *f;
#ifdef SO_LINGER
  struct linger linger;
#endif /* SO_LINGER */
  
  /* Save argv[0]. */
  av0 = av[0];
  saved_argv = av;

  /* Initialize configuration options to their default values. */
  initialize_server_options(&options);

  /* Parse command-line arguments. */
  while ((opt = getopt(ac, av, "f:p:b:k:h:g:diq")) != EOF)
    {
      switch (opt)
	{
	case 'f':
	  config_file_name = optarg;
	  break;
	case 'd':
	  debug_flag = 1;
	  break;
	case 'i':
	  inetd_flag = 1;
	  break;
	case 'q':
	  options.quiet_mode = 1;
	  break;
	case 'b':
	  options.server_key_bits = atoi(optarg);
	  break;
	case 'p':
	  options.port = atoi(optarg);
	  break;
	case 'g':
	  options.login_grace_time = atoi(optarg);
	  break;
	case 'k':
	  options.key_regeneration_time = atoi(optarg);
	  break;
	case 'h':
	  options.host_key_file = optarg;
	  break;
	case '?':
	default:
	  fprintf(stderr, "sshd version %s\n", SSH_VERSION);
	  fprintf(stderr, "Usage: %s [options]\n", av0);
	  fprintf(stderr, "Options:\n");
	  fprintf(stderr, "  -f file    Configuration file (default /etc/sshd_config)\n");
	  fprintf(stderr, "  -d         Debugging mode\n");
	  fprintf(stderr, "  -i         Started from inetd\n");
	  fprintf(stderr, "  -q         Quiet (no logging)\n");
	  fprintf(stderr, "  -p port    Listen on the specified port (default: 22)\n");
	  fprintf(stderr, "  -k seconds Regenerate server key every this many seconds (default: 3600)\n");
	  fprintf(stderr, "  -g seconds Grace period for authentication (default: 300)\n");
	  fprintf(stderr, "  -b bits    Size of server RSA key (default: 768 bits)\n");
	  fprintf(stderr, "  -h file    File from which to read host key (default: %s)\n",
		  HOST_KEY_FILE);
	  exit(1);
	}
    }

  /* Read server configuration options from the configuration file. */
  read_server_config(&options, config_file_name);

  /* Fill in default values for those options not explicitly set. */
  fill_default_server_options(&options);

  /* Check certain values for sanity. */
  if (options.server_key_bits < 512 || 
      options.server_key_bits > 32768)
    {
      fprintf(stderr, "Bad server key size.\n");
      exit(1);
    }
  if (options.port < 1 || options.port > 65535)
    {
      fprintf(stderr, "Bad port number.\n");
      exit(1);
    }

  /* Check that there are no remaining arguments. */
  if (optind < ac)
    {
      fprintf(stderr, "Extra argument %s.\n", av[optind]);
      exit(1);
    }

  /* Initialize the log (it is reinitialized below in case we forked). */
  log_init(av0, debug_flag && !inetd_flag, 
	   debug_flag || options.fascist_logging, 
	   options.quiet_mode, options.log_facility);

  debug("sshd version %s", SSH_VERSION);

  /* Load the host key.  It must have empty passphrase. */
  if (!load_private_key(options.host_key_file, "", 
			&sensitive_data.host_key, &comment))
    {
      if (debug_flag)
	fprintf(stderr, "Could not load host key: %s: %s\n",
		options.host_key_file, strerror(errno));
      else
	{
	  int err = errno;
	  log_init(av0, !inetd_flag, 1, 0, options.log_facility);
	  error("Could not load host key: %.200s: %s", 
		options.host_key_file, strerror(err));
	}
      exit(1);
    }
  xfree(comment);

  /* If not in debugging mode, and not started from inetd, disconnect from
     the controlling terminal, and fork.  The original process exits. */
  if (!debug_flag && !inetd_flag)
    { 
#ifdef TIOCNOTTY
      int fd;
#endif /* TIOCNOTTY */

      /* Fork, and have the parent exit.  The child becomes the server. */
      if (fork())
	exit(0);

      /* Redirect stdin, stdout, and stderr to /dev/null. */
      freopen("/dev/null", "r", stdin);
      freopen("/dev/null", "w", stdout);
      freopen("/dev/null", "w", stderr);

      /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
      fd = open("/dev/tty", O_RDWR|O_NOCTTY);
      if (fd >= 0)
	{
	  (void)ioctl(fd, TIOCNOTTY, NULL);
	  close(fd);
	}
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
      (void)setsid();
#endif /* HAVE_SETSID */
    }

  /* Reinitialize the log (because of the fork above). */
  log_init(av0, debug_flag && !inetd_flag, 
	   debug_flag || options.fascist_logging, 
	   options.quiet_mode, options.log_facility);

  /* Check that server and host key lengths differ sufficiently.  This is
     necessary to make double encryption work with rsaref.  Oh, I hate
     software patents. */
  if (options.server_key_bits > 
      sensitive_data.host_key.bits - SSH_KEY_BITS_RESERVED &&
      options.server_key_bits < 
      sensitive_data.host_key.bits + SSH_KEY_BITS_RESERVED)
    {
      options.server_key_bits = 
	sensitive_data.host_key.bits + SSH_KEY_BITS_RESERVED;
      debug("Forcing server key to %d bits to make it differ from host key.", 
	    options.server_key_bits);
    }

  /* Initialize memory allocation so that any freed MP_INT data will be
     zeroed. */
  rsa_set_mp_memory_allocation();

  /* Do not display messages to stdout in RSA code. */
  rsa_set_verbose(0);

  /* Initialize the random number generator. */
  debug("Initializing random number generator; seed %s", SSH_DAEMON_SEED_FILE);
  random_initialize(&sensitive_data.random_state, SSH_DAEMON_SEED_FILE);

  /* Generate an rsa key. */
  log("Generating %d bit RSA key.", options.server_key_bits);
  rsa_generate_key(&sensitive_data.private_key, &public_key,
		   &sensitive_data.random_state,
		   options.server_key_bits);
  random_stir(&sensitive_data.random_state);
  random_save(&sensitive_data.random_state, SSH_DAEMON_SEED_FILE);
  debug("RSA key generation complete.");
  
  /* Start listening for a socket, unless started from inetd. */
  if (inetd_flag)
    {
      int s1, s2;
      s1 = dup(0); /* stdin */
      s2 = dup(s1);
      sock = dup(s2);
      if (sock <= 2)
	fatal("could not dup sock high enough");
      /* We intentionally do not close the descriptors 0, 1, and 2 as our
	 code for setting the descriptors won\'t work if ttyfd happens to
	 be one of those. */
      debug("inetd socket after dupping: %d", sock);
    }
  else
    {
      /* Create socket for listening. */
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock < 0)
	fatal("socket: %s", strerror(errno));

      /* Set socket options.  We try to make the port reusable and have it
	 close as fast as possible without waiting in unnecessary wait states
	 on close. */
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
#ifdef SO_LINGER
      linger.l_onoff = 0;
      linger.l_linger = 0;
      setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
#endif /* SO_LINGER */

      /* Initialize the socket address. */
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr = options.listen_addr;
      sin.sin_port = htons(options.port);

      /* Bind the socket to the desired port. */
      if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
	  error("bind: %s", strerror(errno));
	  shutdown(sock, 2);
	  close(sock);
	  fatal("Bind to port %d failed.", options.port);
	}

      if (!debug_flag)
	{
	  /* Record our pid in /etc/sshd_pid to make it easier to kill the
	     correct sshd.  We don\'t want to do this before the bind above
	     because the bind will fail if there already is a daemon, and this
	     will overwrite any old pid in the file. */
	  f = fopen(SSH_DAEMON_PID_FILE, "w");
	  if (f)
	    {
	      fprintf(f, "%u\n", (unsigned int)getpid());
	      fclose(f);
	    }
	}

      /* Start listening on the port. */
      log("Server listening on port %d.", options.port);
      if (listen(sock, 5) < 0)
	fatal("listen: %s", strerror(errno));

      /* Schedule server key regeneration alarm. */
      signal(SIGALRM, key_regeneration_alarm);
      alarm(options.key_regeneration_time);

      /* Arrange to restart on SIGHUP.  The handler needs listen_sock. */
      listen_sock = sock;
      signal(SIGHUP, sighup_handler);
      signal(SIGTERM, sigterm_handler);
      signal(SIGQUIT, sigterm_handler);
      
      /* Stay listening for connections until the system crashes or the
	 daemon is killed with a signal. */
      for (;;)
	{
	  /* Wait in accept until there is a connection. */
	  aux = sizeof(sin);
	  newsock = accept(sock, (struct sockaddr *)&sin, &aux);
	  if (newsock < 0)
	    {
	      /* Accept returned an error.  This can happen due to a signal
		 (EINTR), but it appears that we can sometimes get spurious
		 errors due to network problems as well. */
	      if (errno == EINTR)
		continue;
	      error("accept: %s", strerror(errno));
	      continue;
	    }

	  /* Got connection.  Fork a child to handle it, unless we are in
	     debugging mode. */
	  if (debug_flag)
	    {
	      /* In debugging mode.  Close the listening socket, and start
		 processing the connection without forking. */
	      debug("Server will not fork when running in debugging mode.");
	      close(sock);
	      sock = newsock;
	      pid = getpid();
	      break;
	    }
	  else
	    {
	      /* Normal production daemon.  Fork, and have the child process
		 the connection.  The parent continues listening. */
	      if ((pid = fork()) == 0)
		{ 
		  /* Child.  Close the listening socket, and start using
		     the accepted socket.  Reinitialize logging (since our
		     pid has changed).  We break out of the loop to handle
		     the connection. */
		  close(sock);
		  sock = newsock;
		  log_init(av0, debug_flag && !inetd_flag, 
			   options.fascist_logging || debug_flag, 
			   options.quiet_mode, options.log_facility);
		  break;
		}
	    }

	  /* Parent.  Stay in the loop. */
	  if (pid < 0)
	    error("fork: %s", strerror(errno));
	  else
	    debug("Forked child %d.", pid);

	  /* Mark that the key has been used (it was "given" to the child). */
	  key_used = 1;

	  /* Close the new socket (the child is now taking care of it). */
	  close(newsock);

	  /* Wait any exited children.  How can this be so difficult? */
#ifdef HAVE_WAITPID
	  while (waitpid(-1, &wait_status, WNOHANG) > 0)
	    ;
#else /* HAVE_WAITPID */
#ifdef HAVE_WAIT3
	  while (wait3(&wait_status, WNOHANG, NULL) > 0)
	    ;
#else /* HAVE_WAIT3 */
#ifdef HAVE_WAIT4
	  while (wait4(-1, &wait_status, WNOHANG, NULL) > 0)
	    ;
#else /* HAVE_WAIT4 */
	  ERROR_NO_WAIT3_OR_WAIT4_OR_WAITPID;
#endif /* HAVE_WAIT4 */
#endif /* HAVE_WAIT3 */	  
#endif /* HAVE_WAITPID */
	}
    }
  
  /* This is the child processing a new connection. */

  /* Disable the key regeneration alarm.  We will not regenerate the key
     since we are no longer in a position to give it to anyone.  We will
     not restart on SIGHUP since it no longer makes sense. */
  alarm(0);
  signal(SIGALRM, SIG_DFL);
  signal(SIGHUP, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGQUIT, SIG_DFL);

  /* Set socket options for the connection.  We want the socket to close
     as fast as possible without waiting for anything. */
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
#ifdef SO_LINGER
  linger.l_onoff = 0;
  linger.l_linger = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, 
		 sizeof(linger)) < 0)
    error("setsockopt SO_LINGER sock: %s", strerror(errno));
#endif /* SO_LINGER */

  /* Find out who is in the other end. */
  aux = sizeof(sin);
  if (getpeername(sock, (struct sockaddr *)&sin, &aux) < 0)
    fatal("getpeername: %s", strerror(errno));
  client_port = ntohs(sin.sin_port);

  /* Log the connection. */
  log("Connection from %.100s port %d", 
      inet_ntoa(sin.sin_addr), client_port);

  /* Register our connection.  This turns encryption off because we do not
     have a key. */
  packet_set_connection(sock, &sensitive_data.random_state);

  /* Check whether logins are denied from this host. */
  if (options.num_deny_hosts > 0)
    {
      const char *hostname = get_canonical_hostname();
      const char *ipaddr = get_remote_ipaddr();
      int i;
      for (i = 0; i < options.num_deny_hosts; i++)
	if (match_pattern(hostname, options.deny_hosts[i]) ||
	    match_pattern(ipaddr, options.deny_hosts[i]))
	  {
	    log("Connection from %.200s denied.\n", hostname);
	    hostname = "You are not allowed to connect.  Go away!\r\n";
	    write(sock, hostname, strlen(hostname));
	    close(sock);
	    exit(0);
	  }
    }

  /* We don\'t want to listen forever unless the other side successfully
     authenticates itself.  So we set up an alarm which is cleared after
     successful authentication.  A limit of zero indicates no limit.
     Note that we don\'t set the alarm in debugging mode; it is just annoying
     to have the server exit just when you are about to discover the bug. */
  signal(SIGALRM, grace_alarm_handler);
  if (!debug_flag)
    alarm(options.login_grace_time);

  /* Send our protocol version identification. */
  sprintf(buf, "SSH-%d.%d-%s\n", PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
  if (write(sock, buf, strlen(buf)) != strlen(buf))
    fatal("Could not write ident string.");

  /* Read other side\'s version identification. */
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      if (read(sock, &buf[i], 1) != 1)
	fatal("Did not receive ident string.");
      if (buf[i] == '\r')
	{
	  buf[i] = '\n';
	  buf[i + 1] = 0;
	  break;
	}
      if (buf[i] == '\n')
	{
	  /* buf[i] == '\n' */
	  buf[i + 1] = 0;
	  break;
	}
    }
  buf[sizeof(buf) - 1] = 0;
  
  /* Check that the versions match.  In future this might accept several
     versions and set appropriate flags to handle them. */
  if (sscanf(buf, "SSH-%d.%d-%[^\n]\n", &remote_major, &remote_minor, 
	     remote_version) != 3)
    {
      const char *s = "Protocol mismatch.\n";
      (void) write(sock, s, strlen(s));
      close(sock);
      fatal("Bad protocol version identification: %.100s", buf);
    }
  debug("Client protocol version %d.%d; client software version %.100s",
	remote_major, remote_minor, remote_version);
  if (remote_major != PROTOCOL_MAJOR)
    {
      const char *s = "Protocol major versions differ.\n";
      (void) write(sock, s, strlen(s));
      close(sock);
      fatal("Protocol major versions differ: %d vs. %d", 
	    PROTOCOL_MAJOR, remote_major);
    }
  /* Detect whether we are at least protocol version 1.1. */
  remote_protocol_1_1 = (remote_major >= 1 && remote_minor >= 1);
  if (!remote_protocol_1_1)
    {
      packet_send_debug("Warning: You are using an old version of the client.");
      packet_send_debug("The old version is vulnerable to certain attacks (such as playback).");
      packet_send_debug("Upgrading to the latest version is recommended.");
    }


  /* Check whether logins are permitted from this host. */
  if (options.num_allow_hosts > 0)
    {
      const char *hostname = get_canonical_hostname();
      const char *ipaddr = get_remote_ipaddr();
      int i;
      for (i = 0; i < options.num_allow_hosts; i++)
	if (match_pattern(hostname, options.allow_hosts[i]) ||
	    match_pattern(ipaddr, options.allow_hosts[i]))
	  break;
      if (i >= options.num_allow_hosts)
	{
	  log("Connection from %.200s not allowed.\n", hostname);
	  packet_disconnect("Sorry, you are not allowed to connect.");
	  /*NOTREACHED*/
	}
    }

  /* Set the socket into non-blocking mode. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
    log("fcntl O_NONBLOCK: %s", strerror(errno));
#else /* O_NONBLOCK */  
  if (fcntl(sock, F_SETFL, O_NDELAY) < 0)
    log("fcntl O_NDELAY: %s", strerror(errno));
#endif /* O_NONBLOCK */
  
  /* Handle the connection.   We pass as argument whether the connection
     came from a privileged port. */
  do_connection(sock, client_port < 1024);

  /* The connection has been terminated. */
  log("Closing connection to %.100s", inet_ntoa(sin.sin_addr));
  packet_close();
  exit(0);
}

/* Process an incoming connection.  Protocol version identifiers have already
   been exchanged.  This sends server key and performs the key exchange.
   Server and host keys will no longer be needed after this functions. */

void do_connection(int sock, int privileged_port)
{
  int i;
  MP_INT session_key_int;
  unsigned char session_key[SSH_SESSION_KEY_LENGTH];
  unsigned char check_bytes[8];
  char *user;
  unsigned int cipher_type, auth_mask, protocol_flags;

  /* Generate check bytes that the client must send back in the user packet
     in order for it to be accepted; this is used to defy ip spoofing 
     attacks.  Note that this only works against somebody doing IP spoofing 
     from a remote machine; any machine on the local network can still see 
     outgoing packets and catch the random cookie.  This only affects
     rhosts authentication, and this is one of the reasons why it is
     inherently insecure. */
  for (i = 0; i < 8; i++)
    check_bytes[i] = random_get_byte(&sensitive_data.random_state);
  
  /* Send our public key.  We include in the packet 64 bits of random
     data that must be matched in the reply in order to prevent IP spoofing. */
  packet_start(SSH_SMSG_PUBLIC_KEY);
  for (i = 0; i < 8; i++)
    packet_put_char(check_bytes[i]);

  /* Store our public server RSA key. */
  packet_put_int(public_key.bits);
  packet_put_mp_int(&public_key.e);
  packet_put_mp_int(&public_key.n);

  /* Store our public host RSA key. */
  packet_put_int(sensitive_data.host_key.bits);
  packet_put_mp_int(&sensitive_data.host_key.e);
  packet_put_mp_int(&sensitive_data.host_key.n);

  /* Put protocol flags. */
  packet_put_int(0);

  /* Declare which ciphers we support. */
  packet_put_int(cipher_mask());

  /* Declare supported authentication types. */
  auth_mask = 0;
  if (options.rhosts_authentication)
    auth_mask |= 1 << SSH_AUTH_RHOSTS;
  if (options.rhosts_rsa_authentication)
    auth_mask |= 1 << SSH_AUTH_RHOSTS_RSA;
  if (options.rsa_authentication)
    auth_mask |= 1 << SSH_AUTH_RSA;
  if (options.password_authentication)
    auth_mask |= 1 << SSH_AUTH_PASSWORD;
  packet_put_int(auth_mask);

  /* Send the packet and wait for it to be sent. */
  packet_send();
  packet_write_wait();

  debug("Sent %d bit public key and %d bit host key.", 
	public_key.bits, sensitive_data.host_key.bits);

  /* Read clients reply (cipher type and session key). */
  packet_read_expect(SSH_CMSG_SESSION_KEY);

  /* Get cipher type. */
  cipher_type = packet_get_char();

  /* Get check bytes from the packet.  These must match those we sent earlier
     with the public key packet. */
  for (i = 0; i < 8; i++)
    if (check_bytes[i] != packet_get_char())
      packet_disconnect("IP Spoofing check bytes do not match.");

  debug("Encryption type: %.200s", cipher_name(cipher_type));

  /* Get the encrypted integer. */
  mpz_init(&session_key_int);
  packet_get_mp_int(&session_key_int);

  /* Get protocol flags. */
  protocol_flags = packet_get_int();
  packet_set_protocol_flags(protocol_flags);

  /* Decrypt it using our private server key and private host key (key with 
     larger modulus first). */
  if (mpz_cmp(&sensitive_data.private_key.n, &sensitive_data.host_key.n) > 0)
    {
      /* Private key has bigger modulus. */
      assert(sensitive_data.private_key.bits >= 
	     sensitive_data.host_key.bits + SSH_KEY_BITS_RESERVED);
      rsa_private_decrypt(&session_key_int, &session_key_int,
			  &sensitive_data.private_key);
      rsa_private_decrypt(&session_key_int, &session_key_int,
			  &sensitive_data.host_key);
    }
  else
    {
      /* Host key has bigger modulus (or they are equal). */
      assert(sensitive_data.host_key.bits >= 
	     sensitive_data.private_key.bits + SSH_KEY_BITS_RESERVED);
      rsa_private_decrypt(&session_key_int, &session_key_int,
			  &sensitive_data.host_key);
      rsa_private_decrypt(&session_key_int, &session_key_int,
			  &sensitive_data.private_key);
    }

  /* Compute session id for this session. */
  compute_session_id(session_id, check_bytes, sensitive_data.host_key.bits,
		     &sensitive_data.host_key.n, 
		     sensitive_data.private_key.bits,
		     &sensitive_data.private_key.n);

  if (remote_protocol_1_1)
    {
      /* Extract session key from the decrypted integer.  The key is in the 
	 least significant 256 bits of the integer; the first byte of the 
	 key is in the highest bits. */
      mp_linearize_msb_first(session_key, sizeof(session_key), 
			     &session_key_int);

      /* Xor the first 16 bytes of the session key with the session id. */
      for (i = 0; i < 16; i++)
	session_key[i] ^= session_id[i];
    }
  else
    { /* XXX remove this compatibility code later. */
      /* In the old version, the key was taken lsb first, and there was no
	 xor. */
      MP_INT aux;
      /* Extract session key from the decrypted integer.  We take the 256
	 least significant bits of the integer, lsb first. */
      mpz_init(&aux);
      for (i = 0; i < sizeof(session_key); i++)
	{
	  mpz_mod_2exp(&aux, &session_key_int, 8);
	  mpz_div_2exp(&session_key_int, &session_key_int, 8);
	  session_key[i] = mpz_get_ui(&aux);
	}
      mpz_clear(&aux);
    }

  /* Destroy the decrypted integer.  It is no longer needed. */
  mpz_clear(&session_key_int);
  
  /* Set the session key.  From this on all communications will be
     encrypted. */
  packet_set_encryption_key(session_key, SSH_SESSION_KEY_LENGTH, 
			    cipher_type, 0);
  
  /* Destroy our copy of the session key.  It is no longer needed. */
  memset(session_key, 0, sizeof(session_key));

  debug("Received session key; encryption turned on.");

  /* Send an acknowledgement packet.  Note that this packet is sent
     encrypted. */
  packet_start(SSH_SMSG_SUCCESS);
  packet_send();
  packet_write_wait();

  /* Get the name of the user that we wish to log in as. */
  packet_read_expect(SSH_CMSG_USER);

  /* Get the user name. */
  user = packet_get_string(NULL);

  /* Destroy the private and public keys.  They will no longer be needed. */
  rsa_clear_public_key(&public_key);
  rsa_clear_private_key(&sensitive_data.private_key);
  rsa_clear_private_key(&sensitive_data.host_key);

  /* Do the authentication. */
  do_authentication(user, privileged_port);
}

/* Performs authentication of an incoming connection.  Session key has already
   been exchanged and encryption is enabled.  User is the user name to log
   in as (received from the clinet).  Privileged_port is true if the
   connection comes from a privileged port (used for .rhosts authentication). */

void do_authentication(char *user, int privileged_port)
{
  int type;
  int authenticated = 0;
  char *password;
  struct passwd *pw, pwcopy;
  char *client_user;
  unsigned int client_host_key_bits;
  MP_INT client_host_key_e, client_host_key_n;
			 
  /* Verify that the user is a valid user. */
  pw = getpwnam(user);
  if (!pw)
    {
      /* The user does not exist. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();

      /* Keep reading packets, and always respond with a failure.  This is to
	 avoid disclosing whether such a user really exists. */
      for (;;)
	{
	  /* Read a packet.  This will not return if the client disconnects. */
	  (void) packet_read();

	  /* Send failure.  This should be indistinguishable from a failed
	     authentication. */
	  packet_start(SSH_SMSG_FAILURE);
	  packet_send();
	  packet_write_wait();
	}
      /*NOTREACHED*/
      abort();
    }
  
  /* Take a copy of the returned structure. */
  memset(&pwcopy, 0, sizeof(pwcopy));
  pwcopy.pw_name = xstrdup(pw->pw_name);
  pwcopy.pw_passwd = xstrdup(pw->pw_passwd);
  pwcopy.pw_uid = pw->pw_uid;
  pwcopy.pw_gid = pw->pw_gid;
  pwcopy.pw_dir = xstrdup(pw->pw_dir);
  pwcopy.pw_shell = xstrdup(pw->pw_shell);
  pw = &pwcopy;

  /* If we are not running as root, the user must have the same uid as the
     server. */
  if (getuid() != 0 && pw->pw_uid != getuid())
    packet_disconnect("Cannot change user when server not running as root.");

  debug("Attempting authentication for %.100s.", user);

  /* If the user has no password, accept authentication immediately. */
  if (auth_password(user, ""))
    {
      /* Authentication with empty password succeeded. */
      debug("Login for user %.100s accepted without authentication.", user);
      authenticated = 1;
      /* Success packet will be sent after loop below. */
    }
  else
    {
      /* Indicate that authentication is needed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
    }

  /* Loop until the user has been authenticated or the connection is closed. */
  while (!authenticated)
    {
      /* Get a packet from the client. */
      type = packet_read();
      
      /* Process the packet. */
      switch (type)
	{

	case SSH_CMSG_AUTH_RHOSTS:
	  if (!options.rhosts_authentication)
	    {
	      log("Rhosts authentication disabled.");
	      break;
	    }

	  /* Rhosts authentication (also uses /etc/hosts.equiv). */
	  if (!privileged_port)
	    {
	      log("Rhosts authentication not available for connections from unprivileged port.");
	      break;
	    }

	  /* Get client user name.  Note that we just have to trust the client;
	     this is one reason why rhosts authentication is insecure. 
	     (Another is IP-spoofing on a local network.) */
	  client_user = packet_get_string(NULL);

	  /* Try to authenticate using /etc/hosts.equiv and .rhosts. */
	  if (auth_rhosts(pw, client_user))
	    {
	      /* Authentication accepted. */
	      log("Rhosts authentication accepted for %.100s, remote %.100s on %.700s.",
		  user, client_user, get_canonical_hostname());
	      authenticated = 1;
	      xfree(client_user);
	      break;
	    }
	  debug("Rhosts authentication failed for %.100s, remote %.100s.",
		user, client_user);
	  xfree(client_user);
	  break;

	case SSH_CMSG_AUTH_RHOSTS_RSA:
	  if (!options.rhosts_rsa_authentication)
	    {
	      log("Rhosts with RSA authentication disabled.");
	      break;
	    }

	  /* Rhosts authentication (also uses /etc/hosts.equiv) with RSA
	     host authentication. */
	  if (!privileged_port)
	    {
	      log("Rhosts authentication not available for connections from unprivileged port.");
	      break;
	    }

	  /* Get client user name.  Note that we just have to trust the client;
	     root on the client machine can claim to be any user. */
	  client_user = packet_get_string(NULL);

	  /* Get the client host key. */
	  mpz_init(&client_host_key_e);
	  mpz_init(&client_host_key_n);
	  client_host_key_bits = packet_get_int();
	  packet_get_mp_int(&client_host_key_e);
	  packet_get_mp_int(&client_host_key_n);

	  /* Try to authenticate using /etc/hosts.equiv and .rhosts. */
	  if (auth_rhosts_rsa(&sensitive_data.random_state,
			      pw, client_user,
			      client_host_key_bits, &client_host_key_e,
			      &client_host_key_n))
	    {
	      /* Authentication accepted. */
	      authenticated = 1;
	      xfree(client_user);
	      mpz_clear(&client_host_key_e);
	      mpz_clear(&client_host_key_n);
	      break;
	    }
	  debug("Rhosts authentication failed for %.100s, remote %.100s.",
		user, client_user);
	  xfree(client_user);
	  mpz_clear(&client_host_key_e);
	  mpz_clear(&client_host_key_n);
	  break;
	  
	case SSH_CMSG_AUTH_RSA:
	  if (!options.rsa_authentication)
	    {
	      log("RSA authentication disabled.");
	      break;
	    }

	  /* RSA authentication requested. */
	  {
	    MP_INT n;
	    mpz_init(&n);
	    packet_get_mp_int(&n);
	    if (auth_rsa(pw, &n, &sensitive_data.random_state))
	      { 
		/* Successful authentication. */
		mpz_clear(&n);
		log("RSA authentication for %.100s accepted.", user);
		authenticated = 1;
		break;
	      }
	    mpz_clear(&n);
	    debug("RSA authentication for %.100s failed.", user);
	  }
	  break;

	case SSH_CMSG_AUTH_PASSWORD:
	  if (!options.password_authentication)
	    {
	      log("Password authentication disabled.");
	      break;
	    }

	  /* Password authentication requested. */
	  /* Read user password.  It is in plain text, but was transmitted
	     over the encrypted channel so it is not visible to an outside
	     observer. */
	  password = packet_get_string(NULL);

	  /* Try authentication with the password. */
	  if (auth_password(user, password))
	    {
	      /* Successful authentication. */
	      /* Clear the password from memory. */
	      memset(password, 0, strlen(password));
	      xfree(password);
	      log("Password authentication for %.100s accepted.", user);
	      authenticated = 1;
	      break;
	    }
	  debug("Password authentication for %.100s failed.", user);
	  memset(password, 0, strlen(password));
	  xfree(password);
	  break;

	default:
	  /* Any unknown messages will be ignored (and failure returned)
	     during authentication. */
	  log("Unknown message during authentication: type %d", type);
	  break; /* Respond with a failure message. */
	}
      /* If successfully authenticated, break out of loop. */
      if (authenticated)
	break;

      /* Send a message indicating that the authentication attempt failed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
    }

  /* Check if the user is logging in as root and root logins are disallowed. */
  if (pw->pw_uid == 0 && !options.permit_root_login)
    {
      if (forced_command)
	log("Root login accepted for forced command.", forced_command);
      else
	packet_disconnect("ROOT LOGIN REFUSED FROM %.200s", 
			  get_canonical_hostname());
    }

  /* The user has been authenticated and accepted. */
  packet_start(SSH_SMSG_SUCCESS);
  packet_send();
  packet_write_wait();

  /* Perform session preparation. */
  do_authenticated(pw);
}

/* Prepares for an interactive session.  This is called after the user has
   been successfully authenticated.  During this message exchange, pseudo
   terminals are allocated, X11, TCP/IP, and authentication agent forwardings
   are requested, etc. */

void do_authenticated(struct passwd *pw)
{
  int type;
  int have_pty = 0, ptyfd = -1, ttyfd = -1;
  int row, col, xpixel, ypixel;
  char ttyname[64];
  char *command, *term = NULL, *display = NULL, *proto = NULL, *data = NULL;
  struct group *grp;
  gid_t tty_gid;
  mode_t tty_mode;
  
  /* Cancel the alarm we set to limit the time taken for authentication. */
  alarm(0);

  /* Inform the channel mechanism that we are the server side and that
     the client may request to connect to any port at all.  (The user could
     do it anyway, and we wouldn\'t know what is permitted except by the
     client telling us, so we can equally well trust the client not to request
     anything bogus.) */
  channel_permit_all_opens();

  /* We stay in this loop until the client requests to execute a shell or a
     command. */
  while (1)
    {
      /* Get a packet from the client. */
      type = packet_read();
      
      /* Process the packet. */
      switch (type)
	{
	case SSH_CMSG_REQUEST_PTY:
	  if (no_pty_flag)
	    {
	      debug("Allocating a pty not permitted for this authentication.");
	      goto fail;
	    }
	  if (have_pty)
	    packet_disconnect("Protocol error: you already have a pty.");

	  debug("Allocating pty.");

	  /* Allocate a pty and open it. */
	  if (!pty_allocate(&ptyfd, &ttyfd, ttyname))
	    {
	      error("Failed to allocate pty.");
	      goto fail;
	    }

	  /* Determine the group to make the owner of the tty. */
#ifdef TTY_GROUP
	  grp = getgrnam(TTY_GROUP);
#else /* TTY_GROUP */
	  grp = getgrnam("tty");
#endif /* TTY_GROUP */
	  if (grp)
	    {
	      tty_gid = grp->gr_gid;
	      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP;
	    }
	  else
	    {
	      tty_gid = pw->pw_gid;
	      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH;
	    }

	  /* Change ownership of the tty. */
	  (void)chown(ttyname, pw->pw_uid, tty_gid);
	  (void)chmod(ttyname, tty_mode);

	  /* Get TERM from the packet.  Note that the value may be of arbitrary
	     length. */
	  term = packet_get_string(NULL);
	  if (strcmp(term, "") == 0)
	    term = NULL;

	  /* Get window size from the packet. */
	  row = packet_get_int();
	  col = packet_get_int();
	  xpixel = packet_get_int();
	  ypixel = packet_get_int();
	  pty_change_window_size(ptyfd, row, col, xpixel, ypixel);

	  /* Get tty modes from the packet. */
	  tty_parse_modes(ttyfd);

	  /* Indicate that we now have a pty. */
	  have_pty = 1;
	  break;

	case SSH_CMSG_X11_REQUEST_FORWARDING:
	  if (no_x11_forwarding_flag)
	    {
	      debug("X11 forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received request for X11 forwarding.");
	  if (display)
	    packet_disconnect("Protocol error: X11 display already set.");
	  display = x11_create_display();
	  if (!display)
	    goto fail;
	  break;

	case SSH_CMSG_X11_FWD_WITH_AUTH_SPOOFING:
	  if (no_x11_forwarding_flag)
	    {
	      debug("X11 forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received request for X11 forwarding with auth spoofing.");
	  if (display)
	    packet_disconnect("Protocol error: X11 display already set.");
	  proto = packet_get_string(NULL);
	  data = packet_get_string(NULL);
	  display = x11_create_display_inet();
	  if (!display)
	    goto fail;
	  break;

	case SSH_CMSG_AGENT_REQUEST_FORWARDING:
	  if (no_agent_forwarding_flag)
	    {
	      debug("Authentication agent forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received authentication agent forwarding request.");
	  auth_input_request_forwarding(pw);
	  break;

	case SSH_CMSG_PORT_FORWARD_REQUEST:
	  if (no_port_forwarding_flag)
	    {
	      debug("Port forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received TCP/IP port forwarding request.");
	  channel_input_port_forward_request(pw->pw_uid == 0);
	  break;

	case SSH_CMSG_EXEC_SHELL:
	  /* Set interactive/non-interactive mode. */
	  packet_set_interactive(have_pty || display != NULL);
	    
	  if (forced_command != NULL)
	    goto do_forced_command;
	  debug("Forking shell.");
	  if (have_pty)
	    do_exec_pty(NULL, ptyfd, ttyfd, ttyname, pw, term, display, proto,
			data);
	  else
	    do_exec_no_pty(NULL, pw, display, proto, data);
	  return;

	case SSH_CMSG_EXEC_CMD:
	  /* Set interactive/non-interactive mode. */
	  packet_set_interactive(have_pty || display != NULL);

	  if (forced_command != NULL)
	    goto do_forced_command;
	  /* Get command from the packet. */
	  command = packet_get_string(NULL);
	  debug("Executing command '%.500s'", command);
	  if (have_pty)
	    do_exec_pty(command, ptyfd, ttyfd, ttyname, pw, term, display,
			proto, data);
	  else
	    do_exec_no_pty(command, pw, display, proto, data);
	  xfree(command);
	  return;

	default:
	  /* Any unknown messages in this phase are ignored, and a failure
	     message is returned. */
	  log("Unknown packet type received after authentication: %d", type);
	  goto fail;
	}

      /* The request was successfully processed. */
      packet_start(SSH_SMSG_SUCCESS);
      packet_send();
      packet_write_wait();
      continue;

    fail:
      /* The request failed. */
      packet_start(SSH_SMSG_FAILURE);
      packet_send();
      packet_write_wait();
      continue;
      
    do_forced_command:
      /* There is a forced command specified for this login.  Execute it. */
      debug("Executing forced command: %.900s", forced_command);
      if (have_pty)
	do_exec_pty(forced_command, ptyfd, ttyfd, ttyname, pw, term, display,
		    proto, data);
      else
	do_exec_no_pty(forced_command, pw, display, proto, data);
      return;
    }
}

/* This is called to fork and execute a command when we have no tty.  This
   will call do_child from the child, and do_session from the parent after
   setting up file descriptors and such. */

void do_exec_no_pty(const char *command, struct passwd *pw,
		    const char *display, const char *auth_proto,
		    const char *auth_data)
{  
  int pid;

#ifdef USE_PIPES
  int pin[2], pout[2], perr[2];
  /* Allocate pipes for communicating with the program. */
  if (pipe(pin) < 0 || pipe(pout) < 0 || pipe(perr) < 0)
    packet_disconnect("Could not create pipes to communicate with program: %s",
		      strerror(errno));
#else /* USE_PIPES */
  int inout[2], err[2];
  /* Uses socket pairs to communicate with the program. */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) < 0 ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, err) < 0)
    packet_disconnect("Could not create socket pairs to communicate with program: %s",
		      strerror(errno));
#endif /* USE_PIPES */
  
  /* Fork the child. */
  if ((pid = fork()) == 0)
    {
      /* Child.  Reinitialize the log since the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, 
	       options.quiet_mode, options.log_facility);

#ifdef USE_PIPES
      /* Redirect stdin.  We close the parent side of the socket pair,
         and make the child side the standard input. */
      close(pin[1]);
      if (dup2(pin[0], 0) < 0)
	perror("dup2 stdin");
      close(pin[0]);
      
      /* Redirect stdout. */
      close(pout[0]);
      if (dup2(pout[1], 1) < 0)
	perror("dup2 stdout");
      close(pout[1]);

      /* Redirect stderr. */
      close(perr[0]);
      if (dup2(perr[1], 2) < 0)
	perror("dup2 stderr");
      close(perr[1]);
#else /* USE_PIPES */
      /* Redirect stdin, stdout, and stderr.  Stdin and stdout will use the
	 same socket, as some programs (particularly rdist) seem to depend
	 on it. */
      close(inout[1]);
      close(err[1]);
      if (dup2(inout[0], 0) < 0) /* stdin */
	perror("dup2 stdin");
      if (dup2(inout[0], 1) < 0) /* stdout.  Note: same socket as stdin. */
	perror("dup2 stdout");
      if (dup2(err[0], 2) < 0) /* stderr */
	perror("dup2 stderr");
#endif /* USE_PIPES */

      /* Do processing for the child (exec command etc). */
      do_child(command, pw, NULL, display, auth_proto, auth_data);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed");
#ifdef USE_PIPES
  /* We are the parent.  Close the child sides of the pipes. */
  close(pin[0]);
  close(pout[1]);
  close(perr[1]);

  /* Enter the interactive session. */
  do_session(pid, pin[1], pout[0], perr[0]);
  /* do_session has closed pin[1], pout[1], and perr[1]. */
#else /* USE_PIPES */
  /* We are the parent.  Close the child sides of the socket pairs. */
  close(inout[0]);
  close(err[0]);
  
  /* Enter the interactive session.  Note: do_session must be able to handle
     the case that fdin and fdout are the same. */
  do_session(pid, inout[1], inout[1], err[1]);
  /* do_session has closed inout[1] and err[1]. */
#endif /* USE_PIPES */
}

/* This is called to fork and execute a command when we have a tty.  This
   will call do_child from the child, and do_session from the parent after
   setting up file descriptors, controlling tty, updating wtmp, utmp,
   lastlog, and other such operations. */

void do_exec_pty(const char *command, int ptyfd, int ttyfd, 
		 const char *ttyname, struct passwd *pw, const char *term,
		 const char *display, const char *auth_proto, 
		 const char *auth_data)
{
  int pid, fdout;
  const char *hostname;
  struct sockaddr_in from;
  struct hostent *hp;
  int fromlen;
  time_t last_login_time;
  char buf[100], *time_string;
  FILE *f;
  char line[256];

  /* Get IP address of client.  This is needed because we want to record where
     the user logged in from. */
  fromlen = sizeof(from);
  if (getpeername(packet_get_connection(),
		  (struct sockaddr *)&from, &fromlen) < 0)
    fatal("getpeername: %s", strerror(errno));
  
  /* Map the IP address to a host name. */
  hp = gethostbyaddr((char *)&from.sin_addr,
		     sizeof(struct in_addr),
		     from.sin_family);
  if (hp)
    hostname = hp->h_name;
  else
    hostname = inet_ntoa(from.sin_addr);

  /* Get the time when the user last logged in.  Buf will be set to contain
     the hostname the last login was from. */
  last_login_time = get_last_login_time(pw->pw_uid, pw->pw_name,
					buf, sizeof(buf));

  /* Fork the child. */
  if ((pid = fork()) == 0)
    { 
      /* Child.  Reinitialize the log because the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, options.quiet_mode, 
	       options.log_facility);

      /* Close the master side of the pseudo tty. */
      close(ptyfd);

      /* Make the pseudo tty our controlling tty. */
      pty_make_controlling_tty(&ttyfd, ttyname);

      /* Redirect stdin from the pseudo tty. */
      if (dup2(ttyfd, fileno(stdin)) < 0)
	error("dup2 stdin failed: %s", strerror(errno));

      /* Redirect stdout to the pseudo tty. */
      if (dup2(ttyfd, fileno(stdout)) < 0)
	error("dup2 stdin failed: %s", strerror(errno));

      /* Redirect stderr to the pseudo tty. */
      if (dup2(ttyfd, fileno(stderr)) < 0)
	error("dup2 stdin failed: %s", strerror(errno));

      /* Close the extra descriptor for the pseudo tty. */
      close(ttyfd);
      
      /* If the user has logged in before, display the time of last login. */
      if (last_login_time != 0)
	{
	  /* Convert the date to a string. */
	  time_string = ctime(&last_login_time);
	  /* Remove the trailing newline. */
	  if (strchr(time_string, '\n'))
	    *strchr(time_string, '\n') = 0;
	  /* Display the last login time.  Host if displayed if known. */
	  if (strcmp(buf, "") == 0)
	    printf("Last login: %s\r\n", time_string);
	  else
	    printf("Last login: %s from %s\r\n", time_string, buf);
	}

      if (options.print_motd)
	{
	  /* Print /etc/motd if it exists. */
	  f = fopen("/etc/motd", "r");
	  if (f)
	    {
	      while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	      fclose(f);
	    }
	}

      /* Do common processing for the child, such as execing the command. */
      do_child(command, pw, term, display, auth_proto, auth_data);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed: %s", strerror(errno));
  /* Parent.  Close the slave side of the pseudo tty. */
  close(ttyfd);
  
  /* Create another descriptor of the pty master side for use as the standard
     input.  We could use the original descriptor, but this simplifies code
     in do_session.  The descriptor is bidirectional. */
  fdout = dup(ptyfd);
  if (fdout < 0)
    packet_disconnect("dup failed: %s", strerror(errno));

  /* Record that there was a login on that terminal. */
  record_login(pid, ttyname, pw->pw_name, pw->pw_uid, hostname);

  /* Enter interactive session. */
  do_session(pid, ptyfd, fdout, -1);
  /* do_session has closed ptyfd and fdout. */

  /* Record that the user has logged out. */
  record_logout(pid, ttyname);

  /* Release the pseudo-tty. */
  pty_release(ttyname);
}

/* Performs common processing for the child, such as setting up the 
   environment, closing extra file descriptors, setting the user and group 
   ids, and executing the command or shell. */

void do_child(const char *command, struct passwd *pw, const char *term,
	      const char *display, const char *auth_proto, 
	      const char *auth_data)
{
  char *eterm, *euser, *ehome, *eshell, *epath, *edisplay, *eauthfd, *etz;
  char *eclient, *elogname;
  const char *shell, *cp;
  char *env[100];
  char line[256];
  struct sockaddr_in from;
  FILE *f;
  int i, fromlen;

  /* Check /etc/nologin. */
  f = fopen("/etc/nologin", "r");
  if (f)
    { /* /etc/nologin exists.  Print its contents and exit. */
      while (fgets(line, sizeof(line), f))
	fputs(line, stderr);
      fclose(f);
      if (pw->pw_uid != 0)
	{
	  channel_stop_listening();
	  packet_close();
	  exit(254);
	}
    }

  /* Get the shell from the password data.  An empty shell field is legal,
     and means /bin/sh. */
  shell = pw->pw_shell[0] == '\0' ? DEFAULT_SHELL : pw->pw_shell;

  /* Initialize the environment.  In the first part we allocate space for
     all environment variables. */
  if (term)
    eterm = xmalloc(strlen("TERM=") + strlen(term) + 1);
  else
    eterm = NULL;
  euser = xmalloc(strlen("USER=") + strlen(pw->pw_name) + 1);
  elogname = xmalloc(strlen("LOGNAME=") + strlen(pw->pw_name) + 1);
  ehome = xmalloc(strlen("HOME=") + strlen(pw->pw_dir) + 1);
  eshell = xmalloc(strlen("SHELL=") + strlen(shell) + 1);
  epath = xmalloc(strlen("PATH=") + strlen(DEFAULT_PATH) + 1);
  eclient = xmalloc(100); /* clientaddr clientport serverport */
  if (display)
    edisplay = xmalloc(strlen("DISPLAY=") + strlen(display) + 1);
  else
    edisplay = NULL;
  if (get_permanent_fd(pw->pw_shell) < 0)
    {
      if (auth_get_socket_name() != NULL)
	eauthfd = xmalloc(strlen(SSH_AUTHSOCKET_ENV_NAME) + 
			  strlen(auth_get_socket_name()) + 2);
      else
	eauthfd = NULL;
    } 
  else 
    {
      if (auth_get_fd() >= 0)
	eauthfd = xmalloc(strlen(SSH_AUTHFD_ENV_NAME) + 20 + 2);
      else
	eauthfd = NULL;
    }
  /* some systems (e.g. SGIs) don't know anything about our current 
     timezone unless we pass the TZ variable here */
  if (getenv("TZ") != NULL)
    etz = xmalloc(strlen("TZ=") + strlen(getenv("TZ")) + 1);
  else
    etz = NULL;

  /* Format values for all environment variables. */
  if (eterm)
    sprintf(eterm, "TERM=%s", term);
  sprintf(euser, "USER=%s", pw->pw_name);
  sprintf(elogname, "LOGNAME=%s", pw->pw_name);
  sprintf(ehome, "HOME=%s", pw->pw_dir);
  sprintf(eshell, "SHELL=%s", shell);
  sprintf(epath, "PATH=%s", DEFAULT_PATH);
  if (edisplay)
    sprintf(edisplay, "DISPLAY=%s", display);
  if (get_permanent_fd(pw->pw_shell) < 0)
    {
      if (eauthfd)
	sprintf(eauthfd, "%s=%s", SSH_AUTHSOCKET_ENV_NAME,
		auth_get_socket_name());
    }
  else
    {
      if (eauthfd)
	sprintf(eauthfd, "%s=%d", SSH_AUTHFD_ENV_NAME, auth_get_fd());
    }
  if (etz)
    sprintf(etz, "TZ=%s", getenv("TZ"));

  /* Get remote address. */
  fromlen = sizeof(from);
  if (getpeername(packet_get_connection(), (struct sockaddr *)&from, &fromlen) < 0)
    log("getpeername connection (%d) failed: %s", packet_get_connection(),
	strerror(errno));
  sprintf(eclient, "SSH_CLIENT=%.50s %d %d", 
	  inet_ntoa(from.sin_addr), ntohs(from.sin_port), options.port);

  /* Build the environment array. */
  i = 0;
  if (eterm)
    env[i++] = eterm;
  env[i++] = euser;
  env[i++] = elogname;
  env[i++] = ehome;
  env[i++] = eshell;
  env[i++] = epath;
  env[i++] = eclient;
  if (edisplay)
    env[i++] = edisplay;
  if (eauthfd)
    env[i++] = eauthfd;
  if (etz)
    env[i++] = etz;
  env[i++] = NULL;

  /* Display the environment for debugging purposes. */
  debug("Environment:");
  for (i = 0; env[i]; i++)
    debug("  %.200s", env[i]);

  /* Close any extra file descriptors.  Note that there may still be
     descriptors left by system functions.  They will be closed later. */
  close(packet_get_connection());
  channel_close_all();
  endpwent();
  endhostent();

#ifdef HAVE_SETLOGIN
  /* Set login name in the kernel. */
  setlogin(pw->pw_name);
#endif /* HAVE_SETLOGIN */

#ifdef HAVE_USERSEC_H
  /* On AIX, this "sets process credentials".  I am not sure what this
     includes, but it seems to be important.  This also does setuid
     (but we do it below as well just in case). */
  if (setpcred((const char *)pw->pw_name, NULL))
    log("setpcred %.100s: %s", strerror(errno));
#endif /* HAVE_USERSEC_H */

  /* Set uid, gid, and groups. */
  if (getuid() == 0)
    { 
      /* Only change uid if running as root. */
      if (setgid(pw->pw_gid) < 0)
	{
	  perror("setgid");
	  exit(1);
	}
      if (initgroups(pw->pw_name, pw->pw_gid) < 0)
	{
	  perror("initgroups");
	  exit(1);
	}
      endgrent();
      if (setuid(pw->pw_uid) < 0)
	{
	  perror("setuid");
	  exit(1);
	}
    }

  /* Close any extra open file descriptors so that we don\'t have them
     hanging around in clients.  Note that we want to do this after
     initgroups, because at least on Solaris 2.3 it leaves file descriptors
     open. */
  for (i = 3; i < 64; i++)
    {
      if (i == auth_get_fd())
	continue;
      close(i);
    }

  /* Change current directory to the user\'s home directory. */
  if (chdir(pw->pw_dir) < 0)
    fprintf(stderr, "Could not chdir to home directory %.200s: %s\n",
	    pw->pw_dir, strerror(errno));

  /* Add authority data to .Xauthority if appropriate. */
  if (auth_proto != NULL && auth_data != NULL)
    {
      debug("Running %.100s add %.100s %.100s %.100s",
	    XAUTH_PATH, display, auth_proto, auth_data);
      if (fork() == 0)
	{ /* Child */
	  execle(XAUTH_PATH, XAUTH_PATH, "add", display, auth_proto, auth_data,
		 NULL, env);
	  perror("execle");
	  exit(1);
	}
      wait(NULL);
    }

  /* Get the last component of the shell name. */
  cp = strrchr(shell, '/');
  if (cp)
    cp++;
  else
    cp = shell;

  /* If we have no command, execute the shell.  In this case, the shell name
     to be passed in argv[0] is preceded by '-' to indicate that this is
     a login shell. */
  if (!command)
    {
      char buf[256];

      /* Start the shell.  Set initial character to '-'. */
      buf[0] = '-';
      strncpy(buf + 1, cp, sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = 0;
      /* Execute the shell. */
      execle(shell, buf, NULL, env);
      /* Executing the shell failed. */
      perror(shell);
      exit(1);
    }

  /* Execute the command using the user\'s shell.  This uses the -c option
     to execute the command. */
  execle(shell, cp, "-c", command, NULL, env);
  perror(shell);
  exit(1);
}

#ifdef HPSUX_BROKEN_PTYS

/* This SIGCHLD kludge is for HPSUX, because its pty code is broken.
   It does not pass EOF from the slave side to the master side.  */

int do_session_pid;  				/* Pid of the child. */
volatile int do_session_child_terminated;	/* The child has terminated. */
volatile int do_session_wait_status;		/* Status from wait(). */

RETSIGTYPE sigchld_handler(int sig)
{
  int wait_pid;
  debug("Received SIGCHLD.");
  wait_pid = wait((int *)&do_session_wait_status);
  if (wait_pid == -1)
    error("Strange, wait inside SIGCHLD handler returned -1.");
  if (wait_pid != do_session_pid)
    error("Strange, got SIGCHLD and wait returned pid %d but child is %d",
	  wait_pid, do_session_pid);
  if (WIFEXITED(do_session_wait_status) ||
      WIFSIGNALED(do_session_wait_status))
    {
      debug("Child has terminated; wait status 0x%x.", 
	    (unsigned int)do_session_wait_status);
      do_session_child_terminated = 1;
    }
  signal(SIGCHLD, sigchld_handler);
}

#endif /* HPSUX_BROKEN_PTYS */

/* Performs the interactive session.  This handles data transmission between
   the client and the program.  Note that the notion of stdin, stdout, and
   stderr in this function is sort of reversed: this function writes to
   stdin (of the child program), and reads from stdout and stderr (of the
   child program). */

void do_session(int pid, int fdin, int fdout, int fderr)
{
  int max_fd;			/* Max file descriptor number for select(). */
  long stdin_bytes = 0;		/* Number of bytes written to stdin. */
  long stdout_bytes = 0;	/* Number of stdout bytes sent to client. */
  long stderr_bytes = 0;	/* Number of stderr bytes sent to client. */
  long fdout_bytes = 0;		/* Number of stdout bytes read from program. */
  int stdin_eof = 0;		/* EOF message received from client. */
  int fdout_eof = 0;		/* EOF encountered reading from fdout. */
  int fderr_eof = 0;		/* EOF encountered readung from fderr. */
  unsigned int buffer_high;	/* "Soft" max buffer size. */
  Buffer stdin_buffer;		/* Buffer for stdin data. */
  Buffer stdout_buffer;		/* Buffer for stdout data. */
  Buffer stderr_buffer;		/* Buffer for stderr data. */
  int wait_status, wait_pid;	/* Status and pid returned by wait(). */
  int connection = packet_get_connection(); /* Connection to client. */
  int waiting_termination = 0;  /* Have displayed waiting close message. */
  int row, col, xpixel, ypixel;
  int type, len, ret;
  char *data;
  unsigned int data_len;
  char buf[16384];

#ifdef HPSUX_BROKEN_PTYS
  struct timeval tv;

  /* Kludge for HPSUX. */
  do_session_pid = pid;
  do_session_child_terminated = 0;
  signal(SIGCHLD, sigchld_handler);

#endif /* HPSUX_BROKEN_PTYS */

  debug("Entering interactive session.");

  /* Set approximate I/O buffer size. */
  if (packet_is_interactive())
    buffer_high = 4096;
  else
    buffer_high = 64 * 1024;

  /* Initialize max_fd to the maximum of the known file descriptors. */
  max_fd = fdin;
  if (fdout > max_fd)
    max_fd = fdout;
  if (fderr != -1 && fderr > max_fd)
    max_fd = fderr;
  if (connection > max_fd)
    max_fd = connection;

  /* Initialize Initialize buffers. */
  buffer_init(&stdin_buffer);
  buffer_init(&stdout_buffer);
  buffer_init(&stderr_buffer);

  /* If we have no separate fderr (which is the case when we have a pty - there
     we cannot make difference between data sent to stdout and stderr),
     indicate that we have seen an EOF from stderr.  This way we don\'t
     need to check the descriptor everywhere. */
  if (fderr == -1)
    fderr_eof = 1;

  /* We stay in this loop until one of the following happens:
       - We have received EOFs from the program, and all buffered data has
         drained, and has been sent to the client, and there are no active open
         channels. 
       - The client closes the connection.
       - An error is reported via fatal()
       - Select fails.

     The loop is organized as follows:
       1. Process buffered packets from the client.
       2. Process pending EOF from the client.
       3. Send buffered stderr data to client.
       4. Send buffered stdout data to client.
       5. Send channel data to client.
       6. Bail out of loop if all closed, no pending data and no open channels.
       7. Initialize select() masks.
       8. Wait for something to happen in select().
       9. Process channel events.
       10. Input any available data from the client, and buffer for processing.
       11. Read and buffer any available stdout data from the program.
       12. Read and buffer any available stderr data from the program.
       13. Write any buffered stdin data to the program.
       14. Send any buffered packet data to the client.
     After the loop there is cleanup and termination code. */

  for (;;)
    {
      fd_set readset, writeset;
      
      /* Process buffered packets from the client. */
      while ((type = packet_read_poll()) != SSH_MSG_NONE)
	{
	  switch (type)
	    {
	    case SSH_CMSG_STDIN_DATA:
	      /* Stdin data from the client.  Append it to the buffer. */
	      if (fdin == -1)
		break; /* Ignore any data if the client has closed stdin. */
	      data = packet_get_string(&data_len);
	      buffer_append(&stdin_buffer, data, data_len);
	      memset(data, 0, data_len);
	      xfree(data);
	      break;

	    case SSH_CMSG_EOF:
	      /* Eof from the client.  The stdin descriptor to the program
		 will be closed when all buffered data has drained. */
	      debug("EOF received for stdin.");
	      stdin_eof = 1;
	      break;

	    case SSH_CMSG_WINDOW_SIZE:
	      debug("Window change received.");
	      row = packet_get_int();
	      col = packet_get_int();
	      xpixel = packet_get_int();
	      ypixel = packet_get_int();
	      if (fdin != -1)
		pty_change_window_size(fdin, row, col, xpixel, ypixel);
	      break;

	    case SSH_MSG_PORT_OPEN:
	      debug("Received port open request.");
	      channel_input_port_open();
	      break;

	    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
	      debug("Received channel open confirmation.");
	      channel_input_open_confirmation();
	      break;

	    case SSH_MSG_CHANNEL_OPEN_FAILURE:
	      debug("Received channel open failure.");
	      channel_input_open_failure();
	      break;

	    case SSH_MSG_CHANNEL_DATA:
	      channel_input_data();
	      break;

	    case SSH_MSG_CHANNEL_CLOSE:
	      debug("Received channel close.");
	      channel_input_close();
	      break;

	    case SSH_MSG_CHANNEL_CLOSE_CONFIRMATION:
	      debug("Received channel close confirmation.");
	      channel_input_close_confirmation();
	      break;

	    default:
	      /* In this phase, any unexpected messages cause a protocol
		 error.  This is to ease debugging; also, since no 
		 confirmations are sent messages, unprocessed unknown 
		 messages could cause strange problems.  Any compatible 
		 protocol extensions must be negotiated before entering the 
		 interactive session. */
	      packet_disconnect("Protocol error during session: type %d", 
				type);
	    }
	}

      /* If we have received eof, and there is no more pending input data,
	 cause a real eof by closing fdin. */
      if (stdin_eof && fdin != -1 && buffer_len(&stdin_buffer) == 0)
	{
	  if (fdin == fdout)
	    shutdown(fdin, 1); /* We will no longer send. */
	  else
	    close(fdin);
	  fdin = -1;
	}

      /* Send buffered stderr data to the client. */
      while (buffer_len(&stderr_buffer) > 0 && 
	     packet_not_very_much_data_to_write())
	{
	  len = buffer_len(&stderr_buffer);
	  if (packet_is_interactive())
	    {
	      if (len > 512)
		len = 512;
	    }
	  else
	    {
	      if (len > 32768)
		len = 32768;  /* Keep the packets at reasonable size. */
	    }
	  packet_start(SSH_SMSG_STDERR_DATA);
	  packet_put_string(buffer_ptr(&stderr_buffer), len);
	  packet_send();
	  buffer_consume(&stderr_buffer, len);
	  stderr_bytes += len;
	}

      /* Send buffered stdout data to the client. */
      while (buffer_len(&stdout_buffer) > 0 && 
	     packet_not_very_much_data_to_write())
	{
	  len = buffer_len(&stdout_buffer);
	  if (packet_is_interactive())
	    {
	      if (len > 512)
		len = 512;
	    }
	  else
	    {
	      if (len > 32768)
		len = 32768;  /* Keep the packets at reasonable size. */
	    }
	  packet_start(SSH_SMSG_STDOUT_DATA);
	  packet_put_string(buffer_ptr(&stdout_buffer), len);
	  packet_send();
	  buffer_consume(&stdout_buffer, len);
	  stdout_bytes += len;
	}

      /* Send channel data to the client. */
      if (packet_not_very_much_data_to_write())
	channel_output_poll();

      /* Bail out of the loop if the program has closed its output descriptors,
	 and we have no more data to send to the client, and there is no
	 pending buffered data. */
      if (fdout_eof && fderr_eof && !packet_have_data_to_write() &&
	  buffer_len(&stdout_buffer) == 0 && buffer_len(&stderr_buffer) == 0)
	{
	  if (!channel_still_open())
	    goto quit;
	  if (!waiting_termination)
	    {
	      const char *s = 
		"Waiting for forwarded connections to terminate...\r\n";
	      waiting_termination = 1;
	      buffer_append(&stderr_buffer, s, strlen(s));
	    }
	}

      /* Initialize select() masks. */
      FD_ZERO(&readset);

      /* Read packets from the client unless we have too much buffered stdin
	 or channel data. */
      if (buffer_len(&stdin_buffer) < buffer_high &&
	  channel_not_very_much_buffered_data())
	FD_SET(connection, &readset);

      /* If there is not too much data already buffered going to the client,
	 try to get some more data from the program. */
      if (packet_not_very_much_data_to_write())
	{
	  if (!fdout_eof)
	    FD_SET(fdout, &readset);
	  if (!fderr_eof)
	    FD_SET(fderr, &readset);
	}

      FD_ZERO(&writeset);

      /* If we have buffered packet data going to the client, mark that
	 descriptor. */
      if (packet_have_data_to_write())
	FD_SET(connection, &writeset);

      /* If we have buffered data, try to write some of that data to the
	 program. */
      if (fdin != -1 && buffer_len(&stdin_buffer) > 0)
	FD_SET(fdin, &writeset);

      /* Set masks for channel descriptors. */
      channel_prepare_select(&readset, &writeset);

      /* Update the maximum descriptor number if appropriate. */
      if (channel_max_fd() > max_fd)
	max_fd = channel_max_fd();

#ifdef HPSUX_BROKEN_PTYS

      /* Kludge for HPSUX: if the child has terminated, read as much
         is available, and then terminate. */
      if (do_session_child_terminated)
	{
	  tv.tv_usec = 100000;
	  tv.tv_sec = 0;
	}
      else
	{
	  tv.tv_usec = 0;
	  tv.tv_sec = 1000000;
	}

      /* Wait for something to happen.  If you want to implement support
         for SSH_MSG_IGNORE messages being automatically sent, this is
	 a good place to send them (with a random timeout from select). */
      ret = select(max_fd + 1, &readset, &writeset, NULL, &tv);

#else /* HPSUX_BROKEN_PTYS */

      /* Wait for something to happen.  If you want to implement support
         for SSH_MSG_IGNORE messages being automatically sent, this is
	 a good place to send them (with a random timeout from select). */
      ret = select(max_fd + 1, &readset, &writeset, NULL, NULL);

#endif /* HPSUX_BROKEN_PTYS */

      if (ret < 0)
	{
	  if (errno == EINTR)
	    continue;
	  error("select: %s", strerror(errno));
	  goto quit;
	}

#ifdef HPSUX_BROKEN_PTYS

      /* Kludge for HPSUX continues. */
      if (ret == 0 && do_session_child_terminated)
	{
	  if (fdout != -1)
	    close(fdout);
	  if (fderr != -1)
	    close(fderr);
	  if (fdin != -1 && fdin != fdout)
	    close(fdin);
	  fdout = -1;
	  fdout_eof = 1;
	  fderr = -1;
	  fderr_eof = 1;
	  fdin = -1;
	  /* We will keep looping here as long as there is data to send in
	     some direction. */
	}

#endif /* HPSUX_BROKEN_PTYS */

      /* Process any channel events. */
      channel_after_select(&readset, &writeset);

      /* Read and buffer any input data from the client. */
      if (FD_ISSET(connection, &readset))
	{
	  len = read(connection, buf, sizeof(buf));
	  if (len == 0)
	    {
	      /* EOF reading from connection. */
	      log("Connection closed by remote host.");
	      goto quit;
	    }
	  if (len < 0)
	    {
	      /* Error reading from connection. */
	      error("Read error from remote host: %s", strerror(errno));
	      goto quit;
	    }
	  /* Buffer any received data. */
	  packet_process_incoming(buf, len);
	}

      /* Read and buffer any available stdout data from the program. */
      if (!fdout_eof && FD_ISSET(fdout, &readset))
	{
	  len = read(fdout, buf, sizeof(buf));
	  if (len <= 0)
	    fdout_eof = 1;
	  else
	    {
	      buffer_append(&stdout_buffer, buf, len);
	      fdout_bytes += len;
	    }
	}

      /* Read and buffer any available stderr data from the program. */
      if (!fderr_eof && FD_ISSET(fderr, &readset))
	{
	  len = read(fderr, buf, sizeof(buf));
	  if (len <= 0)
	    fderr_eof = 1;
	  else
	    buffer_append(&stderr_buffer, buf, len);
	}

      /* Write buffered data to program stdin. */
      if (fdin != -1 && FD_ISSET(fdin, &writeset))
	{
	  len = write(fdin, buffer_ptr(&stdin_buffer),
		      buffer_len(&stdin_buffer));
	  if (len <= 0)
	    {
	      if (fdin == fdout)
		shutdown(fdin, 1); /* We will no longer send. */
	      else
		close(fdin);
	      fdin = -1;
	    }
	  else
	    {
	      /* Successful write.  Consume the data from the buffer. */
	      buffer_consume(&stdin_buffer, len);
	      /* Update the count of bytes written to the program. */
	      stdin_bytes += len;
	    }
	}
	
      /* Send any buffered packet data to the client. */
      if (FD_ISSET(connection, &writeset))
	packet_write_poll();
    }

 quit:
  /* Cleanup and termination code. */
  /* Send any buffered stdout data to the client. */
  if (buffer_len(&stdout_buffer) > 0)
    {
      packet_start(SSH_SMSG_STDOUT_DATA);
      packet_put_string(buffer_ptr(&stdout_buffer), 
			buffer_len(&stdout_buffer));
      packet_send();
      /* Update the count of sent bytes. */
      stdout_bytes += buffer_len(&stdout_buffer);
    }

  /* Send any buffered stderr data to the client. */
  if (buffer_len(&stderr_buffer) > 0)
    {
      packet_start(SSH_SMSG_STDERR_DATA);
      packet_put_string(buffer_ptr(&stderr_buffer), 
			buffer_len(&stderr_buffer));
      packet_send();
      /* Update the count of sent bytes. */
      stderr_bytes += buffer_len(&stderr_buffer);
    }
  
  /* Wait until all buffered data has been written to the client. */
  packet_write_wait();

  debug("End of interactive session; stdin %ld, stdout (read %ld, sent %ld), stderr %ld bytes.",
	stdin_bytes, fdout_bytes, stdout_bytes, stderr_bytes);

  /* Free and clear the buffers. */
  memset(buf, 0, sizeof(buf));
  buffer_free(&stdin_buffer);
  buffer_free(&stdout_buffer);
  buffer_free(&stderr_buffer);

  /* Close the file descriptors. */
  if (fdout != -1)
    close(fdout);
  if (fdin != -1 && fdin != fdout)
    close(fdin);
  if (fderr != -1)
    close(fderr);

  /* Stop listening for channels; this removes unix domain sockets. */
  channel_stop_listening();
  
  /* Wait for the child to exit.  Get its exit status. */
  wait_pid = wait(&wait_status);
  if (wait_pid < 0)
    {
#ifdef HPSUX_BROKEN_PTYS
      /* HPSUX kludge continues. */
      /* It is possible that the wait was handled by SIGCHLD handler.  This
	 may result in either: this call returning with EINTR, or: this
	 call returning ECHILD. */
      if (do_session_child_terminated)
	wait_status = do_session_wait_status;
      else
	packet_disconnect("wait: %s", strerror(errno));
#else /* HPSUX_BROKEN_PTYS */
      /* Strange, wait for the child failed. */
      packet_disconnect("wait: %s", strerror(errno));
#endif /* HPSUX_BROKEN_PTYS */
    }
  else
    {
      /* Check if it matches the process we forked. */
      if (wait_pid != pid)
	error("Strange, wait returned pid %d, expected %d", wait_pid, pid);
    }

  /* Check if it exited normally. */
  if (WIFEXITED(wait_status))
    {
      /* Yes, normal exit.  Get exit status and send it to the client. */
      debug("Command exited with status %d.", WEXITSTATUS(wait_status));
      packet_start(SSH_SMSG_EXITSTATUS);
      packet_put_int(WEXITSTATUS(wait_status));
      packet_send();
      packet_write_wait();

      /* Wait for exit confirmation.  Note that there might be other
         packets coming before it; however, the program has already died
	 so we just ignore them.  The client is supposed to respond with
	 the confirmation when it receives the exit status. */
      do
	{
	  type = packet_read();
	}
      while (type != SSH_CMSG_EXIT_CONFIRMATION);

      debug("Received exit confirmation.");
      return;
    }

  /* Check if the program terminated due to a signal. */
  if (WIFSIGNALED(wait_status))
    packet_disconnect("Session terminated on signal %d.", 
		      WTERMSIG(wait_status));

  /* Some weird exit cause.  Just exit. */
  packet_disconnect("wait returned status %04x.", wait_status);
  /*NOTREACHED*/
}
