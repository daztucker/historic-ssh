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
 * $Id: sshd.c,v 1.20 1996/09/27 17:19:16 ylo Exp $
 * $Log: sshd.c,v $
 * Revision 1.20  1996/09/27 17:19:16  ylo
 * 	Merged ultrix patches from Corey Satten.
 *
 * Revision 1.19  1996/09/22 22:38:49  ylo
 * 	Added endgrent() before closing all file descriptors.
 *
 * Revision 1.18  1996/09/08 17:40:31  ttsalo
 * 	BSD4.4Lite's _PATH_DEFPATH is checked when defining DEFAULT_PATH.
 * 	(Patch from Andrey A. Chernov <ache@lsd.relcom.eu.net>)
 *
 * Revision 1.17  1996/08/29 14:51:23  ttsalo
 * 	Agent-socket directory handling implemented
 *
 * Revision 1.16  1996/08/22 22:16:24  ylo
 * 	Log remote commands executed by root, and log the fact that a
 * 	remote command was executed by an ordinary user, but not the
 * 	actual command (for privacy reasons).
 *
 * Revision 1.15  1996/08/16 02:47:18  ylo
 * 	Log root logins at LOG_NOTICE.
 *
 * Revision 1.14  1996/08/13 09:04:23  ttsalo
 * 	Home directory, .ssh and .ssh/authorized_keys are now
 * 	checked for wrong owner and group & world writeability.
 *
 * Revision 1.13  1996/08/13 00:23:31  ylo
 * 	When doing X11 forwarding, check the existence of xauth and
 * 	deny forwarding if it doesn't exist.  This makes copying
 * 	binaries compiled on one system to other systems easier.
 *
 * 	Run /etc/sshrc with /bin/sh instead of the user's shell.
 *
 * Revision 1.12  1996/07/29 04:58:54  ylo
 * 	Add xauth data also for `hostname`/unix:$display as some X
 * 	servers actually seem to use this version.  (Kludge to work
 * 	around X11 bug.)
 *
 * Revision 1.11  1996/07/15 23:21:55  ylo
 * 	Don't allow more than five password authentication attempts,
 * 	and log attempts after the first one.
 *
 * Revision 1.10  1996/07/12 07:28:02  ttsalo
 * 	Small ultrix patch
 *
 * Revision 1.9  1996/06/05 17:57:34  ylo
 * 	If /etc/nologin exists, print that fact in plain text before
 * 	printing the actual contents.  I am getting too many
 * 	complaints about it.
 *
 * Revision 1.8  1996/06/03 19:25:49  ylo
 * 	Fixed a typo.
 *
 * Revision 1.7  1996/05/29 07:41:46  ylo
 * 	Added arguments to userfile_init.
 *
 * Revision 1.6  1996/05/29 07:16:38  ylo
 * 	Disallow any user names that start with a '-' or '+' (or '@',
 * 	just to be sure).  There is some indication that getpw* might
 * 	returns such names on some systems with NIS.  Ouuuch!
 *
 * Revision 1.5  1996/05/28 16:41:14  ylo
 * 	Merged Cray patches from Wayne Schroeder.
 * 	Use setsid instead of setpgrp on ultrix.
 *
 * Revision 1.4  1996/04/26 00:22:51  ylo
 * 	Improved error messages related to reading host key.
 * 	Fixed ip addr in "Closing connection" message.
 *
 * Revision 1.3  1996/04/22 23:49:47  huima
 * Changed protocol version to 1.4, added calls to emulate module.
 *
 * Revision 1.2  1996/02/18  21:49:51  ylo
 * 	Moved userfile_uninit to proper place.
 * 	Use setluid if it exists (at least OSF/1).
 *
 * Revision 1.1.1.1  1996/02/18 21:38:13  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.31  1995/10/02  01:28:59  ylo
 * 	Include sys/syslog.h if NEED_SYS_SYSLOG_H.
 * 	Print proper ETCDIR in usage().
 *
 * Revision 1.30  1995/09/27  02:54:43  ylo
 * 	Fixed a minor error.
 *
 * Revision 1.29  1995/09/27  02:49:06  ylo
 * 	Fixed syntax errors.
 *
 * Revision 1.28  1995/09/27  02:18:51  ylo
 * 	Added support for SCO unix.
 * 	Added support for .hushlogin.
 * 	Read $HOME/.environment.
 * 	Pass X11 proto and cookie in stdin instead of command line.
 * 	Added support for $HOME/.ssh/rc and /etc/sshrc.
 *
 * Revision 1.27  1995/09/25  00:03:53  ylo
 * 	Added screen number.
 * 	Don't display motd and login time if executing a command.
 *
 * Revision 1.26  1995/09/22  22:22:34  ylo
 * 	Fixed a bug in the new environment code.
 *
 * Revision 1.25  1995/09/21  17:16:49  ylo
 * 	Fixes to libwrap code.
 * 	Fixed problem in wait() in key regeneration.  Now only
 * 	ackquires light noise at regeneration.
 * 	Support for ignore_rhosts.
 * 	Don't use X11 forwarding with spoofing if no xauth.
 * 	Rewrote the code to initialize the environment in the child.
 * 	Added code to read /etc/environment into child environment.
 * 	Fixed setpcred argument type.
 *
 * Revision 1.24  1995/09/11  17:35:53  ylo
 * 	Added libwrap support.
 * 	Log daemon name without path.
 *
 * Revision 1.23  1995/09/10  23:43:32  ylo
 * 	Added a newline in xauth message.
 *
 * Revision 1.22  1995/09/10  23:29:43  ylo
 * 	Renamed sigchld_handler main_sigchld_handler to avoid
 * 	conflict.
 *
 * Revision 1.21  1995/09/10  23:26:53  ylo
 * 	Child xauth line printed with fprintf instead of debug().
 *
 * Revision 1.20  1995/09/10  22:43:17  ylo
 * 	Added uid-swapping stuff.
 * 	Moved do_session to serverloop.c and renamed it server_loop.
 * 	Changed SIGCHLD handling.
 * 	Merged OSF/1 C2 security stuff.
 *
 * Revision 1.19  1995/09/09  21:26:47  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
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
#include "userfile.h"
#include "emulate.h"
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */
#ifdef HAVE_ULIMIT_H
#include <ulimit.h>
#endif /* HAVE_ULIMIT_H */

#ifdef LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* LIBWRAP */

#ifdef CRAY
#include <udb.h>
#include <unistd.h>
#include <sys/category.h>
extern char *setlimits();
#endif

#ifdef _PATH_BSHELL
#define DEFAULT_SHELL		_PATH_BSHELL
#else
#define DEFAULT_SHELL		"/bin/sh"
#endif

#ifndef DEFAULT_PATH
#ifdef _PATH_USERPATH
#define DEFAULT_PATH		_PATH_USERPATH
#else
#ifdef _PATH_DEFPATH
#define	DEFAULT_PATH		_PATH_DEFPATH
#else
#define DEFAULT_PATH	"/bin:/usr/bin:/usr/ucb:/usr/bin/X11:/usr/local/bin"
#endif
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

/* argv[0] without path. */
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
struct envstring *custom_environment = NULL; 
			  /* RSA authentication "environment=" options. */

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

/* This is set to true when SIGHUP is received. */
int received_sighup = 0;

/* Public side of the server key.  This value is regenerated regularly with
   the private key. */
RSAPublicKey public_key;

/* Prototypes for various functions defined later in this file. */
void do_connection(int privileged_port);
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
	      const char *auth_data, const char *ttyname);


/* Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
   the effect is to reread the configuration file (and to regenerate
   the server key). */

RETSIGTYPE sighup_handler(int sig)
{
  received_sighup = 1;
  signal(SIGHUP, sighup_handler);
}

/* Called from the main program after receiving SIGHUP.  Restarts the 
   server. */

void sighup_restart()
{
  log("Received SIGHUP; restarting.");
  close(listen_sock);
  execv(saved_argv[0], saved_argv);
  log("RESTART FAILED: av[0]='%s', error: %s.", 
      saved_argv[0], strerror(errno));
  exit(1);
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

/* SIGCHLD handler.  This is called whenever a child dies.  This will then 
   reap any zombies left by exited c. */

RETSIGTYPE main_sigchld_handler(int sig)
{
  int status;
  wait(&status);
  signal(SIGCHLD, main_sigchld_handler);
}

/* Signal handler for the alarm after the login grace period has expired. */

RETSIGTYPE grace_alarm_handler(int sig)
{
  /* Close the connection. */
  packet_close();
  
  /* Log error and exit. */
  fatal_severity(SYSLOG_SEVERITY_INFO,
		 "Timeout before authentication.");
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
      random_acquire_light_environmental_noise(&sensitive_data.random_state);
      rsa_generate_key(&sensitive_data.private_key, &public_key, 
		       &sensitive_data.random_state, options.server_key_bits);
      random_save(&sensitive_data.random_state, geteuid(),
		  options.random_seed_file);
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
  int opt, aux, sock_in, sock_out, newsock, i, pid, on = 1;
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
  saved_argv = av;
  if (strchr(av[0], '/'))
    av0 = strrchr(av[0], '/') + 1;
  else
    av0 = av[0];

  /* Prevent core dumps to avoid revealing sensitive information. */
  signals_prevent_core();

  /* Set SIGPIPE to be ignored. */
  signal(SIGPIPE, SIG_IGN);

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
	  fprintf(stderr, "sshd version %s [%s]\n", SSH_VERSION, HOSTTYPE);
	  fprintf(stderr, "Usage: %s [options]\n", av0);
	  fprintf(stderr, "Options:\n");
	  fprintf(stderr, "  -f file    Configuration file (default %s/sshd_config)\n", ETCDIR);
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

  debug("sshd version %.100s [%.100s]", SSH_VERSION, HOSTTYPE);

  /* Load the host key.  It must have empty passphrase. */
  if (!load_private_key(geteuid(), options.host_key_file, "", 
			&sensitive_data.host_key, &comment))
    {
      if (debug_flag)
	{
	  fprintf(stderr, "Could not load host key: %.200s\n",
		  options.host_key_file);
	  fprintf(stderr, "Please check that you have sufficient permissions and the file exists.\n");
	}
      else
	{
	  int err = errno;
	  log_init(av0, !inetd_flag, 1, 0, options.log_facility);
	  error("Could not load host key: %.200s.  Check path and permissions.", 
		options.host_key_file);
	}
      exit(1);
    }
  xfree(comment);

#ifdef SCO
  (void) set_auth_parameters(ac, av);
#endif

#ifdef HAVE_OSF1_C2_SECURITY
  initialize_osf_security(ac, av);
#endif /* HAVE_OSF1_C2_SECURITY */

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
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
	error("setsid: %.100s", strerror(errno));
#endif
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
  debug("Initializing random number generator; seed file %.200s", 
	options.random_seed_file);
  random_initialize(&sensitive_data.random_state, geteuid(),
		    options.random_seed_file);
  
  /* Chdir to the root directory so that the current disk can be unmounted
     if desired. */
  chdir("/");
  
  /* Start listening for a socket, unless started from inetd. */
  if (inetd_flag)
    {
      int s1, s2;
      s1 = dup(0);  /* Make sure descriptors 0, 1, and 2 are in use. */
      s2 = dup(s1);
      sock_in = dup(0);
      sock_out = dup(1);
      /* We intentionally do not close the descriptors 0, 1, and 2 as our
	 code for setting the descriptors won\'t work if ttyfd happens to
	 be one of those. */
      debug("inetd sockets after dupping: %d, %d", sock_in, sock_out);

      /* Generate an rsa key. */
      log("Generating %d bit RSA key.", options.server_key_bits);
      rsa_generate_key(&sensitive_data.private_key, &public_key,
		       &sensitive_data.random_state,
		   options.server_key_bits);
      random_save(&sensitive_data.random_state, geteuid(),
		  options.random_seed_file);
      log("RSA key generation complete.");
    }
  else
    {
      /* Create socket for listening. */
      listen_sock = socket(AF_INET, SOCK_STREAM, 0);
      if (listen_sock < 0)
	fatal("socket: %.100s", strerror(errno));

      /* Set socket options.  We try to make the port reusable and have it
	 close as fast as possible without waiting in unnecessary wait states
	 on close. */
      setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, 
		 sizeof(on));
#ifdef SO_LINGER
      linger.l_onoff = 1;
      linger.l_linger = 15;
      setsockopt(listen_sock, SOL_SOCKET, SO_LINGER, (void *)&linger, 
		 sizeof(linger));
#endif /* SO_LINGER */

      /* Initialize the socket address. */
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr = options.listen_addr;
      sin.sin_port = htons(options.port);

      /* Bind the socket to the desired port. */
      if (bind(listen_sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
	  error("bind: %.100s", strerror(errno));
	  shutdown(listen_sock, 2);
	  close(listen_sock);
	  fatal("Bind to port %d failed.", options.port);
	}

      if (!debug_flag)
	{
	  /* Record our pid in /etc/sshd_pid to make it easier to kill the
	     correct sshd.  We don\'t want to do this before the bind above
	     because the bind will fail if there already is a daemon, and this
	     will overwrite any old pid in the file. */
	  f = fopen(options.pid_file, "w");
	  if (f)
	    {
	      fprintf(f, "%u\n", (unsigned int)getpid());
	      fclose(f);
	    }
	}

      /* Start listening on the port. */
      log("Server listening on port %d.", options.port);
      if (listen(listen_sock, 5) < 0)
	fatal("listen: %.100s", strerror(errno));

      /* Generate an rsa key. */
      log("Generating %d bit RSA key.", options.server_key_bits);
      rsa_generate_key(&sensitive_data.private_key, &public_key,
		       &sensitive_data.random_state,
		       options.server_key_bits);
      random_save(&sensitive_data.random_state, geteuid(),
		  options.random_seed_file);
      log("RSA key generation complete.");

      /* Schedule server key regeneration alarm. */
      signal(SIGALRM, key_regeneration_alarm);
      alarm(options.key_regeneration_time);

      /* Arrange to restart on SIGHUP.  The handler needs listen_sock. */
      signal(SIGHUP, sighup_handler);
      signal(SIGTERM, sigterm_handler);
      signal(SIGQUIT, sigterm_handler);
      
      /* Arrange SIGCHLD to be caught. */
      signal(SIGCHLD, main_sigchld_handler);

      /* Stay listening for connections until the system crashes or the
	 daemon is killed with a signal. */
      for (;;)
	{
	  if (received_sighup)
	    sighup_restart();
	  /* Wait in accept until there is a connection. */
	  aux = sizeof(sin);
	  newsock = accept(listen_sock, (struct sockaddr *)&sin, &aux);
	  if (received_sighup)
	    sighup_restart();
	  if (newsock < 0)
	    {
	      if (errno == EINTR)
		continue;
	      error("accept: %.100s", strerror(errno));
	      continue;
	    }

#ifdef LIBWRAP
	  {
	    struct request_info req;
	    request_init(&req, RQ_DAEMON, av0, RQ_FILE, newsock, NULL);
	    fromhost(&req);
	    if (!hosts_access(&req)) 
	      {
		error("Connection from %.500s refused by tcp_wrappers.",
		      eval_client(&req));
		shutdown(newsock, 2);
		close(newsock);
		continue;
	      }
	    /* if from inet: refuse(&req); */
	    log("connect from %.500s", eval_client(&req));
	  }
#endif /* LIBWRAP */

	  /* Got connection.  Fork a child to handle it, unless we are in
	     debugging mode. */
	  if (debug_flag)
	    {
	      /* In debugging mode.  Close the listening socket, and start
		 processing the connection without forking. */
	      debug("Server will not fork when running in debugging mode.");
	      close(listen_sock);
	      sock_in = newsock;
	      sock_out = newsock;
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
		  close(listen_sock);
		  sock_in = newsock;
		  sock_out = newsock;
		  log_init(av0, debug_flag && !inetd_flag, 
			   options.fascist_logging || debug_flag, 
			   options.quiet_mode, options.log_facility);
		  break;
		}
	    }

	  /* Parent.  Stay in the loop. */
	  if (pid < 0)
	    error("fork: %.100s", strerror(errno));
	  else
	    debug("Forked child %d.", pid);

	  /* Mark that the key has been used (it was "given" to the child). */
	  key_used = 1;

	  /* Close the new socket (the child is now taking care of it). */
	  close(newsock);
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
  signal(SIGCHLD, SIG_DFL);

  /* Set socket options for the connection.  We want the socket to close
     as fast as possible without waiting for anything.  If the connection
     is not a socket, these will do nothing. */
  /* setsockopt(sock_in, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)); */
#ifdef SO_LINGER
  linger.l_onoff = 1;
  linger.l_linger = 15;
  setsockopt(sock_in, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
#endif /* SO_LINGER */

  /* Register our connection.  This turns encryption off because we do not
     have a key. */
  packet_set_connection(sock_in, sock_out, &sensitive_data.random_state);

  /* Log the connection. */
  log("Connection from %.100s port %d", 
      get_remote_ipaddr(), get_remote_port());

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
	    write(sock_out, hostname, strlen(hostname));
	    close(sock_in);
	    close(sock_out);
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
  sprintf(buf, "SSH-%d.%d-%.100s\n", 
	  PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
  if (write(sock_out, buf, strlen(buf)) != strlen(buf))
    fatal_severity(SYSLOG_SEVERITY_INFO,
		   "Could not write ident string.");

  /* Read other side\'s version identification. */
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      if (read(sock_in, &buf[i], 1) != 1)
	fatal_severity(SYSLOG_SEVERITY_INFO,
		       "Did not receive ident string.");
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
      (void) write(sock_out, s, strlen(s));
      close(sock_in);
      close(sock_out);
      fatal_severity(SYSLOG_SEVERITY_INFO,
		     "Bad protocol version identification: %.100s", buf);
    }
  debug("Client protocol version %d.%d; client software version %.100s",
	remote_major, remote_minor, remote_version);

  switch (check_emulation(remote_major, remote_minor,
			  NULL, NULL))
    {
    case EMULATE_MAJOR_VERSION_MISMATCH:
      {
	const char *s = "Protocol major versions differ.\n";
	(void) write(sock_out, s, strlen(s));
	close(sock_in);
	close(sock_out);
	fatal_severity(SYSLOG_SEVERITY_INFO,
		       "Protocol major versions differ: %d vs. %d", 
		       PROTOCOL_MAJOR, remote_major);
      }
      break;
    case EMULATE_VERSION_REALLY_TOO_OLD:
    case EMULATE_VERSION_TOO_OLD:
      packet_disconnect("Your ssh version is too old and is no "
			"longer supported.  Please install a newer version.");
      break;
    case EMULATE_VERSION_TOO_NEW:
      packet_disconnect("This server does not support your "
			"new ssh version.");
      break;      
    default:
      /* just continue... */
      break;
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

  packet_set_nonblocking();
  
  /* Handle the connection.   We pass as argument whether the connection
     came from a privileged port. */
  do_connection(get_remote_port() < 1024);

  /* Try to remove authentication socket and directory */
  auth_delete_socket(NULL);
  
  /* The connection has been terminated. */
  log("Closing connection to %.100s", get_remote_ipaddr());
  packet_close();
  exit(0);
}

/* Process an incoming connection.  Protocol version identifiers have already
   been exchanged.  This sends server key and performs the key exchange.
   Server and host keys will no longer be needed after this functions. */

void do_connection(int privileged_port)
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
  packet_put_int(SSH_PROTOFLAG_HOST_IN_FWD_OPEN);

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

  /* Extract session key from the decrypted integer.  The key is in the 
     least significant 256 bits of the integer; the first byte of the 
     key is in the highest bits. */
  mp_linearize_msb_first(session_key, sizeof(session_key), 
			 &session_key_int);
  
  /* Xor the first 16 bytes of the session key with the session id. */
  for (i = 0; i < 16; i++)
    session_key[i] ^= session_id[i];

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

/* Returns true if logging in as the specified user is permitted.  Returns
   false if login is not permitted (e.g., the account is expired). */

int login_permitted(char *user)
{
#ifdef HAVE_USERSEC_H
  char *expiration, current_time[100], normalized[100];
  int rlogin_permitted;
  time_t t;
  struct tm *tm;
  if (setuserdb(S_READ) < 0)
    {
      debug("setuserdb S_READ failed.");
      return 0;
    }
  if (getuserattr(user, S_RLOGINCHK, &rlogin_permitted, SEC_BOOL) < 0)
    {
      debug("getuserattr S_RLOGINCHK failed.");
      enduserdb();
      return 0;
    }
  if (getuserattr(user, S_EXPIRATION, &expiration, SEC_CHAR) < 0)
    {
      debug("getuserattr S_EXPIRATION failed.");
      enduserdb();
      return 0;
    }
  if (!rlogin_permitted)
    {
      debug("Remote logins to account %.100s not permitted by user profile.",
	    user);
      enduserdb();
      return 0;
    }
  if (strcmp(expiration, "0") == 0)
    {
      /* The account does not expire - return success immediately. */
      enduserdb();
      return 1;
    }
  if (strlen(expiration) != 10)
    {
      debug("Account %.100s expiration date is in wrong format.", user);
      enduserdb();
      return 0;
    }
  t = time(NULL);
  tm = localtime(&t);
  sprintf(current_time, "%04d%02d%02d%02d%02d",
	  tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	  tm->tm_hour, tm->tm_min);
  if (expiration[8] < '7') /* Assume year < 70 is 20YY. */
    strcpy(normalized, "20");
  else
    strcpy(normalized, "19");
  strcat(normalized, expiration + 8);
  strcat(normalized, expiration);
  normalized[12] = '\0';
  if (strcmp(normalized, current_time) < 0)
    {
      debug("Account %.100s has expired - access denied.", user);
      enduserdb();
      return 0;
    }
  enduserdb();
#endif /* HAVE_USERSEC_H */
  return 1;
}

/* This function is called by userfile_init after fork() to clean up sensitive
   data.  RSA keys have already been destroyed before we get here.  However,
   normal encryption keys and socket connections (access rights) need to
   be destroyed. */

static void sshd_userfile_cleanup(void *context)
{
  endpwent();

  /* Close the connection descriptors; note that this is the child, and the 
     server will still have the socket open, and it is important that we
     do not shutdown it.  Note that the descriptors cannot be closed before
     building the environment, as we call get_remote_ipaddr there. */
  if (packet_get_connection_in() == packet_get_connection_out())
    close(packet_get_connection_in());
  else
    {
      close(packet_get_connection_in());
      close(packet_get_connection_out());
    }
  /* Close all descriptors related to channels.  They will still remain
     open in the parent. */
  channel_close_all();

  /* Set dummy encryption key to clear key data from memory.  This key will
     never be used. */
  packet_set_encryption_key((void *)"0123456789ABCDEF0123456789ABCDEF",
			    16, SSH_CIPHER_3DES, 0);
}

/* Performs authentication of an incoming connection.  Session key has already
   been exchanged and encryption is enabled.  User is the user name to log
   in as (received from the clinet).  Privileged_port is true if the
   connection comes from a privileged port (used for .rhosts authentication).*/

void do_authentication(char *user, int privileged_port)
{
  int type;
  int authenticated = 0;
  int authentication_type = 0;
  char *password;
  struct passwd *pw, pwcopy;
  char *client_user;
  unsigned int client_host_key_bits;
  MP_INT client_host_key_e, client_host_key_n;
  int password_attempts = 0;
			 
  /* Verify that the user is a valid user.  We disallow usernames starting
     with any characters that are commonly used to start NIS entries. */
  pw = getpwnam(user);
  if (!pw || user[0] == '-' || user[0] == '+' || user[0] == '@' ||
      !login_permitted(user))
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

  /* Start a child process running on the user's uid.  It will be used to
     read files in the user's directory.  Note that the private host
     key has already been cleared when this is called.  We still want to
     clean up at least the encryption keys. */
  userfile_init(pw->pw_name, pw->pw_uid, pw->pw_gid,
		sshd_userfile_cleanup, NULL);

  /* If we are not running as root, the user must have the same uid as the
     server. */
  if (getuid() != 0 && pw->pw_uid != getuid())
    packet_disconnect("Cannot change user when server not running as root.");

  debug("Attempting authentication for %.100s.", user);

  /* If the user has no password, accept authentication immediately. */
  if (options.password_authentication && auth_password(user, ""))
    {
      /* Authentication with empty password succeeded. */
      debug("Login for user %.100s accepted without authentication.", user);
      authentication_type = SSH_AUTH_PASSWORD;
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
	  if (auth_rhosts(pw, client_user, options.ignore_rhosts,
			  options.strict_modes))
	    {
	      /* Authentication accepted. */
	      log("Rhosts authentication accepted for %.100s, remote %.100s on %.700s.",
		  user, client_user, get_canonical_hostname());
	      authentication_type = SSH_AUTH_RHOSTS;
	      authenticated = 1;
	      xfree(client_user);
	      break;
	    }
	  debug("Rhosts authentication failed for '%.100s', remote '%.100s', host '%.200s'.",
		user, client_user, get_canonical_hostname());
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
			      &client_host_key_n, options.ignore_rhosts,
			      options.strict_modes))
	    {
	      /* Authentication accepted. */
	      authentication_type = SSH_AUTH_RHOSTS_RSA;
	      authenticated = 1;
	      xfree(client_user);
	      mpz_clear(&client_host_key_e);
	      mpz_clear(&client_host_key_n);
	      break;
	    }
	  debug("RhostsRSA authentication failed for '%.100s', remote '%.100s', host '%.200s'.",
		user, client_user, get_canonical_hostname());
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
	    if (auth_rsa(pw, &n, &sensitive_data.random_state,
			 options.strict_modes))
	      { 
		/* Successful authentication. */
		mpz_clear(&n);
		log("RSA authentication for %.100s accepted.", user);
		authentication_type = SSH_AUTH_RSA;
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

	  if (password_attempts >= 5)
	    { /* Too many password authentication attempts. */
	      packet_disconnect("Too many password authentication attempts from %.100s for user %.100s.",
				get_canonical_hostname(), user);
	      /*NOTREACHED*/
	    }
	  
	  /* Count password authentication attempts, and log if appropriate. */
	  if (password_attempts > 0)
	    {
	      /* Log failures if attempted more than once. */
	      debug("Password authentication failed for user %.100s from %.100s.",
		    user, get_canonical_hostname());
	    }
	  password_attempts++;

	  /* Try authentication with the password. */
	  if (auth_password(user, password))
	    {
	      /* Successful authentication. */
	      /* Clear the password from memory. */
	      memset(password, 0, strlen(password));
	      xfree(password);
	      log("Password authentication for %.100s accepted.", user);
	      authentication_type = SSH_AUTH_PASSWORD;
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
  if (pw->pw_uid == 0 && options.permit_root_login == 1)
    {
      if (authentication_type == SSH_AUTH_PASSWORD)
	packet_disconnect("ROOT LOGIN REFUSED FROM %.200s", 
			  get_canonical_hostname());
    }
  else
    if (pw->pw_uid == 0 && options.permit_root_login == 0)
      {
	if (forced_command)
	  log("Root login accepted for forced command.", forced_command);
	else
	  packet_disconnect("ROOT LOGIN REFUSED FROM %.200s", 
			    get_canonical_hostname());
      }

  /* Log root logins with severity NOTICE. */
  if (pw->pw_uid == 0)
    log_severity(SYSLOG_SEVERITY_NOTICE, "ROOT LOGIN as '%.100s' from %.100s",
		 pw->pw_name, get_canonical_hostname());
  
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
  int compression_level = 0, enable_compression_after_reply = 0;
  int have_pty = 0, ptyfd = -1, ttyfd = -1;
  int row, col, xpixel, ypixel, screen;
  unsigned long max_size;
  char ttyname[64];
  char *command, *term = NULL, *display = NULL, *proto = NULL, *data = NULL;
  struct group *grp;
  gid_t tty_gid;
  mode_t tty_mode;
  struct stat st;
  
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
	case SSH_CMSG_REQUEST_COMPRESSION:
	  compression_level = packet_get_int();
	  if (compression_level < 1 || compression_level > 9)
	    {
	      packet_send_debug("Received illegal compression level %d.",
				compression_level);
	      goto fail;
	    }
	  /* Enable compression after we have responded with SUCCESS. */
	  enable_compression_after_reply = 1;
	  break;

	case SSH_CMSG_MAX_PACKET_SIZE:
	  /* Get maximum size from paket. */
	  max_size = packet_get_int();

	  /* Make sure that it is acceptable. */
	  if (max_size < 4096 || max_size > 256 * 1024)
	    {
	      packet_send_debug("Received illegal max packet size %lu.",
				max_size);
	      goto fail;
	    }

	  /* Set the size and return success. */
	  packet_set_max_size(max_size);
	  break;

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
	  if (!options.x11_forwarding)
	    {
	      packet_send_debug("X11 forwarding disabled in server configuration file.");
	      goto fail;
	    }
#ifdef XAUTH_PATH
	  if (no_x11_forwarding_flag)
	    {
	      packet_send_debug("X11 forwarding not permitted for this authentication.");
	      goto fail;
	    }
	  debug("Received request for X11 forwarding with auth spoofing.");
	  if (display)
	    packet_disconnect("Protocol error: X11 display already set.");

	  /* Check whether we have xauth installed on this machine (in case
	     the binary was moved from elsewhere). */
	  if (stat(XAUTH_PATH, &st) < 0)
	    {
	      packet_send_debug("Remote host has no X11 installed.");
	      goto fail;
	    }

	  /* Process the request. */
	  proto = packet_get_string(NULL);
	  data = packet_get_string(NULL);
	  if (packet_get_protocol_flags() & SSH_PROTOFLAG_SCREEN_NUMBER)
	    screen = packet_get_int();
	  else
	    screen = 0;
	  display = x11_create_display_inet(screen);
	  if (!display)
	    goto fail;
	  break;
#else /* XAUTH_PATH */
	  /* No xauth program; we won't accept forwarding with spoofing. */
	  packet_send_debug("No xauth program; cannot forward with spoofing.");
	  goto fail;
#endif /* XAUTH_PATH */

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
	  packet_set_interactive(have_pty || display != NULL, 
				 options.keepalives);
	    
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
	  packet_set_interactive(have_pty || display != NULL,
				 options.keepalives);

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

      /* Enable compression now that we have replied if appropriate. */
      if (enable_compression_after_reply)
	{
	  enable_compression_after_reply = 0;
	  packet_start_compression(compression_level);
	}

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
   will call do_child from the child, and server_loop from the parent after
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
    packet_disconnect("Could not create pipes: %.100s",
		      strerror(errno));
#else /* USE_PIPES */
  int inout[2], err[2];
  /* Uses socket pairs to communicate with the program. */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) < 0 ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, err) < 0)
    packet_disconnect("Could not create socket pairs: %.100s",
		      strerror(errno));
#endif /* USE_PIPES */

  /* We no longer need the child running on user's privileges. */
  userfile_uninit();
  
  /* Fork the child. */
  if ((pid = fork()) == 0)
    {
      /* Child.  Reinitialize the log since the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, 
	       options.quiet_mode, options.log_facility);

#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
	error("setsid: %.100s", strerror(errno));
#endif
#endif /* HAVE_SETSID */

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
      do_child(command, pw, NULL, display, auth_proto, auth_data, NULL);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed: %.100s", strerror(errno));
#ifdef USE_PIPES
  /* We are the parent.  Close the child sides of the pipes. */
  close(pin[0]);
  close(pout[1]);
  close(perr[1]);

  /* Enter the interactive session. */
  server_loop(pid, pin[1], pout[0], perr[0]);
  /* server_loop has closed pin[1], pout[1], and perr[1]. */
#else /* USE_PIPES */
  /* We are the parent.  Close the child sides of the socket pairs. */
  close(inout[0]);
  close(err[0]);
  
  /* Enter the interactive session.  Note: server_loop must be able to handle
     the case that fdin and fdout are the same. */
  server_loop(pid, inout[1], inout[1], err[1]);
  /* server_loop has closed inout[1] and err[1]. */
#endif /* USE_PIPES */
}

struct pty_cleanup_context
{
  const char *ttyname;
  int pid;
};

/* Function to perform cleanup if we get aborted abnormally (e.g., due to a
   dropped connection). */

void pty_cleanup_proc(void *context)
{
  struct pty_cleanup_context *cu = context;

  debug("pty_cleanup_proc called");

  /* Record that the user has logged out. */
  record_logout(cu->pid, cu->ttyname);

  /* Release the pseudo-tty. */
  pty_release(cu->ttyname);
}

/* This is called to fork and execute a command when we have a tty.  This
   will call do_child from the child, and server_loop from the parent after
   setting up file descriptors, controlling tty, updating wtmp, utmp,
   lastlog, and other such operations. */

void do_exec_pty(const char *command, int ptyfd, int ttyfd, 
		 const char *ttyname, struct passwd *pw, const char *term,
		 const char *display, const char *auth_proto, 
		 const char *auth_data)
{
  int pid, fdout;
  const char *hostname;
  time_t last_login_time;
  char buf[100], *time_string;
  char line[256];
  struct stat st;
  int quiet_login;
  struct sockaddr_in from;
  int fromlen;
  struct pty_cleanup_context cleanup_context;

  /* We no longer need the child running on user's privileges. */
  userfile_uninit();

  /* Get remote host name. */
  hostname = get_canonical_hostname();

  /* Get the time when the user last logged in.  Buf will be set to contain
     the hostname the last login was from. */
  last_login_time = get_last_login_time(pw->pw_uid, pw->pw_name,
					buf, sizeof(buf));

  /* Fork the child. */
  if ((pid = fork()) == 0)
    { 
      pid = getpid();

      /* Child.  Reinitialize the log because the pid has changed. */
      log_init(av0, debug_flag && !inetd_flag, debug_flag, options.quiet_mode, 
	       options.log_facility);

#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
	error("setsid: %.100s", strerror(errno));
#endif
#endif /* HAVE_SETSID */

      /* Close the master side of the pseudo tty. */
      close(ptyfd);

      /* Make the pseudo tty our controlling tty. */
      pty_make_controlling_tty(&ttyfd, ttyname);

      /* Redirect stdin from the pseudo tty. */
      if (dup2(ttyfd, fileno(stdin)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stdout to the pseudo tty. */
      if (dup2(ttyfd, fileno(stdout)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stderr to the pseudo tty. */
      if (dup2(ttyfd, fileno(stderr)) < 0)
	error("dup2 stdin failed: %.100s", strerror(errno));

      /* Close the extra descriptor for the pseudo tty. */
      close(ttyfd);

      /* Get IP address of client.  This is needed because we want to record 
	 where the user logged in from.  If the connection is not a socket,
	 let the ip address be 0.0.0.0. */
      memset(&from, 0, sizeof(from));
      if (packet_get_connection_in() == packet_get_connection_out())
	{
	  fromlen = sizeof(from);
	  if (getpeername(packet_get_connection_in(),
			  (struct sockaddr *)&from, &fromlen) < 0)
	    fatal("getpeername: %.100s", strerror(errno));
	}

      /* Record that there was a login on that terminal. */
      record_login(pid, ttyname, pw->pw_name, pw->pw_uid, hostname, 
		   &from);

      /* Check if .hushlogin exists.  Note that we cannot use userfile
         here because we are in the child. */
      sprintf(line, "%.200s/.hushlogin", pw->pw_dir);
      quiet_login = stat(line, &st) >= 0;
      
      /* If the user has logged in before, display the time of last login. 
         However, don't display anything extra if a command has been 
	 specified (so that ssh can be used to execute commands on a remote
	 machine without users knowing they are going to another machine). */
      if (command == NULL && last_login_time != 0 && !quiet_login)
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

      /* Print /etc/motd unless a command was specified or printing it was
	 disabled in server options.  Note that some machines appear to
	 print it in /etc/profile or similar. */
      if (command == NULL && options.print_motd && !quiet_login)
	{
	  FILE *f;

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
      do_child(command, pw, term, display, auth_proto, auth_data, ttyname);
      /*NOTREACHED*/
    }
  if (pid < 0)
    packet_disconnect("fork failed: %.100s", strerror(errno));
  /* Parent.  Close the slave side of the pseudo tty. */
  close(ttyfd);
  
#ifdef ultrix		/* corey */
  setpgrp(0,0);		/* disconnect from child's process group */
#endif /* ultrix */

  /* Create another descriptor of the pty master side for use as the standard
     input.  We could use the original descriptor, but this simplifies code
     in server_loop.  The descriptor is bidirectional. */
  fdout = dup(ptyfd);
  if (fdout < 0)
    packet_disconnect("dup failed: %.100s", strerror(errno));

  /* Add a cleanup function to clear the utmp entry and record logout time
     in case we call fatal() (e.g., the connection gets closed). */
  cleanup_context.pid = pid;
  cleanup_context.ttyname = ttyname;
  fatal_add_cleanup(pty_cleanup_proc, (void *)&cleanup_context);

  /* Enter interactive session. */
  server_loop(pid, ptyfd, fdout, -1);
  /* server_loop has closed ptyfd and fdout. */

  /* Cancel the cleanup function. */
  fatal_remove_cleanup(pty_cleanup_proc, (void *)&cleanup_context);

  /* Record that the user has logged out. */
  record_logout(pid, ttyname);

  /* Release the pseudo-tty. */
  pty_release(ttyname);
}

/* Sets the value of the given variable in the environment.  If the variable
   already exists, its value is overriden. */

void child_set_env(char ***envp, unsigned int *envsizep, const char *name,
		   const char *value)
{
  unsigned int i, namelen;
  char **env;

  /* Find the slot where the value should be stored.  If the variable already
     exists, we reuse the slot; otherwise we append a new slot at the end
     of the array, expanding if necessary. */
  env = *envp;
  namelen = strlen(name);
  for (i = 0; env[i]; i++)
    if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
      break;
  if (env[i])
    {
      /* Name already exists.  Reuse the slot. */
      xfree(env[i]);
    }
  else
    {
      /* New variable.  Expand the array if necessary. */
      if (i >= (*envsizep) - 1)
	{
	  (*envsizep) += 50;
	  env = (*envp) = xrealloc(env, (*envsizep) * sizeof(char *));
	}

      /* Need to set the NULL pointer at end of array beyond the new 
	 slot. */
      env[i + 1] = NULL;
    }

  /* Allocate space and format the variable in the appropriate slot. */
  env[i] = xmalloc(strlen(name) + 1 + strlen(value) + 1);
  sprintf(env[i], "%s=%s", name, value);
}

/* Reads environment variables from the given file and adds/overrides them
   into the environment.  If the file does not exist, this does nothing.
   Otherwise, it must consist of empty lines, comments (line starts with '#')
   and assignments of the form name=value.  No other forms are allowed. */

void read_environment_file(char ***env, unsigned int *envsize,
			   const char *filename)
{
  FILE *f;
  char buf[4096];
  char *cp, *value;
  
  /* Open the environment file.  Note that this is only called on the user's
     uid, and thus should not cause security problems. */
  f = fopen(filename, "r");
  if (!f)
    return;  /* Not found. */
  
  /* Process each line. */
  while (fgets(buf, sizeof(buf), f))
    {
      /* Skip leading whitespace. */
      for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
	;

      /* Ignore empty and comment lines. */
      if (!*cp || *cp == '#' || *cp == '\n')
	continue;

      /* Remove newline. */
      if (strchr(cp, '\n'))
	*strchr(cp, '\n') = '\0';

      /* Find the equals sign.  Its lack indicates badly formatted line. */
      value = strchr(cp, '=');
      if (value == NULL)
	{
	  fprintf(stderr, "Bad line in %.100s: %.200s\n", filename, buf);
	  continue;
	}

      /* Replace the equals sign by nul, and advance value to the value 
	 string. */
      *value = '\0';
      value++;

      /* Set the value in environment. */
      child_set_env(env, envsize, cp, value);
    }
  
  fclose(f);
}


#ifdef HAVE_ETC_DEFAULT_LOGIN

/* Gets the value of the given variable in the environment.  If the
   variable does not exist, returns NULL. */

char *child_get_env(char **env, const char *name)
{
  unsigned int i, namelen;

  namelen = strlen(name);

  for (i = 0; env[i]; i++)
    if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
      break;
  if (env[i])
    return &env[i][namelen + 1];
  else
    return NULL;
}

/* Processes /etc/default/login; this involves things like environment
   settings, ulimit, etc.  This file exists at least on Solaris 2.x. */

void read_etc_default_login(char ***env, unsigned int *envsize,
			    const char *user_shell, uid_t user_uid)
{
  unsigned int defenvsize;
  char **defenv, *def;
  int i;

  /* Read /etc/default/login into a separate temporary environment. */
  defenvsize = 10;
  defenv = xmalloc(defenvsize * sizeof(char *));
  defenv[0] = NULL;
  read_environment_file(&defenv, &defenvsize, "/etc/default/login");

  /* Set SHELL if ALTSHELL is YES. */
  def = child_get_env(defenv, "ALTSHELL");
  if (def != NULL && strcmp(def, "YES") == 0)
    child_set_env(env, envsize, "SHELL", user_shell);

  /* Set PATH from SUPATH if we are logging in as root, and PATH
     otherwise.  If neither of these exists, we use the default ssh
     path. */
  if (user_uid == 0)
    def = child_get_env(defenv, "SUPATH");
  else
    def = child_get_env(defenv, "PATH");
  if (def != NULL)
    child_set_env(env, envsize, "PATH", def);
  else
    child_set_env(env, envsize, "PATH", DEFAULT_PATH ":" BINDIR);

  /* Set TZ if TIMEZONE is defined and we haven't inherited a value
     for TZ. */
  def = getenv("TZ");
  if (def == NULL)
    def = child_get_env(defenv, "TIMEZONE");
  if (def != NULL)
    child_set_env(env, envsize, "TZ", def);

  /* Set HZ if defined. */
  def = child_get_env(defenv, "HZ");
  if (def != NULL)
    child_set_env(env, envsize, "HZ", def);

  /* Set up the default umask if UMASK is defined. */
  def = child_get_env(defenv, "UMASK");
  if (def != NULL)
    {
      int i, value;

      for (value = i = 0; 
	   def[i] && isdigit(def[i]) && def[i] != '8' && def[i] != '9'; 
	   i++)
	value = value * 8 + def[i] - '0';

      umask(value);
    }

  /* Set up the file size ulimit if ULIMIT is set. */
  def = child_get_env(defenv, "ULIMIT");
  if (def != NULL && atoi(def) > 0)
    ulimit(UL_SETFSIZE, atoi(def));

  /* Free the temporary environment. */
  for (i = 0; defenv[i]; i++)
    xfree(defenv[i]);
  xfree(defenv);
}

#endif /* HAVE_ETC_DEFAULT_LOGIN */

/* Performs common processing for the child, such as setting up the 
   environment, closing extra file descriptors, setting the user and group 
   ids, and executing the command or shell. */

void do_child(const char *command, struct passwd *pw, const char *term,
	      const char *display, const char *auth_proto, 
	      const char *auth_data, const char *ttyname)
{
  const char *shell, *cp;
  char buf[256];
  FILE *f;
  unsigned int envsize, i;
  char **env;
  extern char **environ;
  struct stat st;
  char *argv[10];
  uid_t user_uid;
  gid_t user_gid;
  char *user_dir;
  char *user_name;
  char *user_shell;
  char *remote_ip;
  int remote_port;
  
  /* Check /etc/nologin. */
  f = fopen("/etc/nologin", "r");
  if (f)
    { /* /etc/nologin exists.  Print its contents and exit. */
      /* Print a message about /etc/nologin existing; I am getting
	 questions because of this every week. */
      fprintf(stderr, "Logins are currently denied by /etc/nologin:\n");
      while (fgets(buf, sizeof(buf), f))
	fputs(buf, stderr);
      fclose(f);
      if (pw->pw_uid != 0)
	exit(254);
    }

  if (command != NULL)
    {
      /* If executing a command as root, log the whole command.  For normal
	 users, don't log the command, because logging it would be a
	 violation of the user's privacy (and even potentially illegal with
	 respect to privacy/data protection laws in some countries). */
      if (pw->pw_uid == 0)
	log("executing remote command as root: %.200s", command);
      else
	log("executing remote command as user %.200s", pw->pw_name);
    }
  
#ifdef HAVE_SETLOGIN
  /* Set login name in the kernel.  Warning: setsid() must be called before
     this. */
  if (setlogin(pw->pw_name) < 0)
    error("setlogin failed: %.100s", strerror(errno));
#endif /* HAVE_SETLOGIN */

#ifdef HAVE_USERSEC_H
  /* On AIX, this "sets process credentials".  I am not sure what this
     includes, but it seems to be important.  This also does setuid
     (but we do it below as well just in case). */
  if (setpcred((char *)pw->pw_name, NULL))
    log("setpcred %.100s: %.100s", strerror(errno));
#endif /* HAVE_USERSEC_H */

  /* Save some data that will be needed so that we can do certain cleanups
     before we switch to user's uid.  (We must clear all sensitive data 
     and access rights from memory before doing that.) */
  user_uid = pw->pw_uid;
  user_gid = pw->pw_gid;
  user_dir = xstrdup(pw->pw_dir);
  user_name = xstrdup(pw->pw_name);
  user_shell = xstrdup(pw->pw_shell);
  remote_ip = xstrdup(get_remote_ipaddr());
  remote_port = get_remote_port();

  /* Close the connection descriptors; note that this is the child, and the 
     server will still have the socket open, and it is important that we
     do not shutdown it.  Note that the descriptors cannot be closed before
     building the environment, as we call get_remote_ipaddr there. */
  if (packet_get_connection_in() == packet_get_connection_out())
    close(packet_get_connection_in());
  else
    {
      close(packet_get_connection_in());
      close(packet_get_connection_out());
    }
  /* Close all descriptors related to channels.  They will still remain
     open in the parent. */
  channel_close_all();

  /* Close any extra file descriptors.  Note that there may still be
     descriptors left by system functions.  They will be closed later. */
  endpwent();
  endhostent();

  /* Set dummy encryption key to clear information about the key from
     memory.  This key will never be used. */
  packet_set_encryption_key((void *)"0123456789ABCDEF0123456789ABCDEF", 32,
			    SSH_CIPHER_3DES, 0);

  /* Clear any remaining data in the random number generator. */
  random_clear(&sensitive_data.random_state);

  /* The sensitive private keys were cleared already before authentication. */

  /* Clear the data structure, just in case. */
  memset(&sensitive_data, 0, sizeof(sensitive_data));

  /* Close any extra open file descriptors so that we don\'t have them
     hanging around in clients.  Note that we want to do this after
     initgroups, because at least on Solaris 2.3 it leaves file descriptors
     open. */
  endgrent();
  for (i = 3; i < 64; i++)
    {
      if (i == auth_get_fd())
	continue;
      close(i);
    }

  /* At this point, this process should no longer be holding any confidential
     information, as changing uid below will permit the user to attach with
     a debugger on some machines. */

#ifdef CRAY   /* set up accounting account number, job, limits, permissions  */
  if (cray_setup(user_uid, user_name) < 0)
    fatal("Failure performing Cray job setup for user %d.",(int)user_uid);
#endif

  /* Set uid, gid, and groups. */
  if (getuid() == 0 || geteuid() == 0)
    { 
      if (setgid(user_gid) < 0)
	{
	  perror("setgid");
	  exit(1);
	}
#ifdef HAVE_INITGROUPS
      /* Initialize the group list. */
      if (initgroups(user_name, user_gid) < 0)
	{
	  perror("initgroups");
	  exit(1);
	}
#endif /* HAVE_INITGROUPS */
      endgrent();

#ifdef HAVE_SETLUID
      /* Set login uid, if we have setluid(). */
      if (setluid(user_uid) < 0)
	fatal("setluid %d: %s", (int)user_uid, strerror(errno));
#endif /* HAVE_SETLUID */

      /* Permanently switch to the desired uid. */
      if (setuid(user_uid) < 0)
	fatal("setuid %d: %s", (int)user_uid, strerror(errno));
    }

  if (getuid() != user_uid || geteuid() != user_uid)
    fatal("Failed to set uids to %d.", (int)user_uid);

  /* Reset signals to their default settings before starting the user
     process. */
  signals_reset();

  /* Get the shell from the password data.  An empty shell field is legal,
     and means /bin/sh. */
  shell = (user_shell[0] == '\0') ? DEFAULT_SHELL : user_shell;

  /* Initialize the environment.  In the first part we allocate space for
     all environment variables. */
  envsize = 100;
  env = xmalloc(envsize * sizeof(char *));
  env[0] = NULL;

  /* Set basic environment. */
  child_set_env(&env, &envsize, "USER", user_name);
  child_set_env(&env, &envsize, "LOGNAME", user_name);
  child_set_env(&env, &envsize, "HOME", user_dir);
  child_set_env(&env, &envsize, "PATH", DEFAULT_PATH ":" BINDIR);

  /* Let it inherit timezone if we have one. */
  if (getenv("TZ"))
    child_set_env(&env, &envsize, "TZ", getenv("TZ"));

#ifdef MAIL_SPOOL_DIRECTORY
  sprintf(buf, "%.200s/%.50s", MAIL_SPOOL_DIRECTORY, user_name);
  child_set_env(&env, &envsize, "MAIL", buf);
#else /* MAIL_SPOOL_DIRECTORY */
#ifdef MAIL_SPOOL_FILE
  sprintf(buf, "%.200s/%.50s", user_dir, MAIL_SPOOL_FILE);
  child_set_env(&env, &envsize, "MAIL", buf);
#endif /* MAIL_SPOOL_FILE */
#endif /* MAIL_SPOOL_DIRECTORY */

#ifdef HAVE_ETC_DEFAULT_LOGIN
  /* Read /etc/default/login; this exists at least on Solaris 2.x.  Note
     that we are already running on the user's uid. */
  read_etc_default_login(&env, &envsize, user_shell, user_uid);
#else /* HAVE_ETC_DEFAULT_LOGIN */
  /* Normal systems set SHELL by default. */
  child_set_env(&env, &envsize, "SHELL", shell);
#endif /* HAVE_ETC_DEFAULT_LOGIN */

  /* Set custom environment options from RSA authentication. */
  while (custom_environment) 
    {
      struct envstring *ce = custom_environment;
      char *s = ce->s;
      int i;
      for (i = 0; s[i] != '=' && s[i]; i++)
	;
      if (s[i] == '=') 
	{
	  s[i] = 0;
	  child_set_env(&env, &envsize, s, s + i + 1);
	}
      custom_environment = ce->next;
      xfree(ce->s);
      xfree(ce);
    }

  /* Set SSH_CLIENT. */
  sprintf(buf, "%.50s %d %d", remote_ip, remote_port, options.port);
  child_set_env(&env, &envsize, "SSH_CLIENT", buf);

  /* Set SSH_TTY if we have a pty. */
  if (ttyname)
    child_set_env(&env, &envsize, "SSH_TTY", ttyname);

  /* Set TERM if we have a pty. */
  if (term)
    child_set_env(&env, &envsize, "TERM", term);

  /* Set DISPLAY if we have one. */
  if (display)
    child_set_env(&env, &envsize, "DISPLAY", display);

  /* Set variable for forwarded authentication connection, if we have one. */
  if (get_permanent_fd(shell) < 0)
    {
      if (auth_get_socket_name() != NULL)
	child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME, 
		      auth_get_socket_name());
    }
  else
    if (auth_get_fd() >= 0)
      {
	sprintf(buf, "%d", auth_get_fd());
	child_set_env(&env, &envsize, SSH_AUTHFD_ENV_NAME, buf);
      }

  /* Read environment variable settings from /etc/environment.  (This exists
     at least on AIX, but could be useful also elsewhere.) */
  read_environment_file(&env, &envsize, "/etc/environment");

  /* Read $HOME/.ssh/environment. */
  sprintf(buf, "%.200s/.ssh/environment", user_dir);
  read_environment_file(&env, &envsize, buf);

  /* If debugging, dump the environment to stderr. */
  if (debug_flag)
    {
      fprintf(stderr, "Environment:\n");
      for (i = 0; env[i]; i++)
	fprintf(stderr, "  %.200s\n", env[i]);
    }

  /* Change current directory to the user\'s home directory. */
  if (chdir(user_dir) < 0)
    fprintf(stderr, "Could not chdir to home directory %s: %s\n",
	    user_dir, strerror(errno));

  /* Must take new environment into use so that .ssh/rc, /etc/sshrc and
     xauth are run in the proper environment. */
  environ = env;

  /* Run $HOME/.ssh/rc, /etc/sshrc, or xauth (whichever is found first
     in this order).  Note that we are already running on the user's uid. */
  if (stat(SSH_USER_RC, &st) >= 0)
    {
      sprintf(buf, "%.100s %.100s", shell, SSH_USER_RC);

      if (debug_flag)
	fprintf(stderr, "Running %s\n", buf);

      f = popen(buf, "w");
      if (f)
	{
	  if (auth_proto != NULL && auth_data != NULL)
	    fprintf(f, "%s %s\n", auth_proto, auth_data);
	  pclose(f);
	}
      else
	fprintf(stderr, "Could not run %s\n", SSH_USER_RC);
    }
  else
    if (stat(SSH_SYSTEM_RC, &st) >= 0)
      {
	sprintf(buf, "%.100s %.100s", "/bin/sh", SSH_SYSTEM_RC);

	if (debug_flag)
	  fprintf(stderr, "Running %s\n", buf);

	f = popen(buf, "w");
	if (f)
	  {
	    if (auth_proto != NULL && auth_data != NULL)
	      fprintf(f, "%s %s\n", auth_proto, auth_data);
	    pclose(f);
	  }
	else
	  fprintf(stderr, "Could not run %s\n", SSH_SYSTEM_RC);
      }
#ifdef XAUTH_PATH
    else
      {
	/* Add authority data to .Xauthority if appropriate. */
	if (auth_proto != NULL && auth_data != NULL)
	  {
	    if (debug_flag)
	      fprintf(stderr, "Running %.100s add %.100s %.100s %.100s\n",
		      XAUTH_PATH, display, auth_proto, auth_data);

	    signal(SIGPIPE, SIG_IGN);
	    
	    f = popen(XAUTH_PATH " -q -", "w");
	    if (f)
	      {
		fprintf(f, "add %s %s %s\n", display, auth_proto, auth_data);
		cp = strchr(display, ':');
		if (cp)
		  fprintf(f, "add %.*s/unix%s %s %s\n",
			  cp - display, display, cp, auth_proto, auth_data);
		pclose(f);
	      }
	    else
	      fprintf(stderr, "Could not run %s -q -\n", XAUTH_PATH);

	    signal(SIGPIPE, SIG_DFL);
	  }
      }
#endif /* XAUTH_PATH */

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
      argv[0] = buf;
      argv[1] = NULL;
      execve(shell, argv, env);
      /* Executing the shell failed. */
      perror(shell);
      exit(1);
    }

  /* Execute the command using the user's shell.  This uses the -c option
     to execute the command. */
  argv[0] = (char *)cp;
  argv[1] = "-c";
  argv[2] = (char *)command;
  argv[3] = NULL;
  execve(shell, argv, env);
  perror(shell);
  exit(1);
}

#ifdef CRAY
/*
 On a Cray, set the account number for the current process to the user's 
 default account.  If this is not done, the process will have an account 
 of zero and accounting (Cray System Accounting and/or SDSC Resource
 Management (realtime)) will not operate correctly.

 This routine also calls setjob to set up an Cray Job (also known 
 as a Session).  This is needed for CRI's Cray System Accounting 
 and SDSC's Resource Management accounting/management system.

 It also calls setlimit, to set up limits and permissions.
 
 Wayne Schroeder
 San Diego Supercomputer Center
 schroeder@sdsc.edu
 
*/
int cray_setup(uid, username)
uid_t uid;
char *username;
{
  register struct udb *p;
  extern struct udb *getudb();
  int i, j;
  int accts[MAXVIDS];
  int naccts;
  int err, jid;
  char *sr;
  int pid;

  /* Find all of the accounts for a particular user */
  err = setudb();    /* open and rewind the Cray User DataBase */
  if(err != 0)
    {
      debug("UDB open failure");
      return(-1);
    }
  naccts = 0;
  while ((p = getudb()) != UDB_NULL) 
    {
      if (p->ue_uid == -1) break;
      if(uid == p->ue_uid) 
	{
	  for(j = 0; p->ue_acids[j] != -1 && j < MAXVIDS; j++) 
	    {
	      accts[naccts] = p->ue_acids[j];
	      naccts++;
	    }
	}
    }
  endudb();        /* close the udb */
  if (naccts == 0 || accts[0] == 0)
    {
      debug("No Cray accounts found");
      return(-1);
    }
 
  /* Perhaps someday we'll prompt users who have multiple accounts
     to let them pick one (like CRI's login does), but for now just set 
     the account to the first entry. */
  if (acctid(0, accts[0]) < 0) 
    {
      debug("System call acctid failed, accts[0]=%d",accts[0]);
      return(-1);
    } 
 
  /* Now call setjob to create a new job(/session).  This assigns a new Session
     ID and session table entry to the calling process.  This process will be
     the first process in the job/session. */
  jid = setjob(uid, 0);
  if (jid < 0) 
    {
      debug("System call setjob failure");
      return(-1);
    }

  /* Now set limits, including CPU time for the (interactive) job and process,
     and set up permissions (for chown etc), etc.  This is via an internal CRI
     routine, setlimits, used by CRI's login. */

  pid = getpid();
  sr = setlimits(username, C_PROC, pid, UDBRC_INTER);
  if (sr != NULL) 
    {
      debug(sr);
      return(-1);
    }
  sr = setlimits(username, C_JOB, jid, UDBRC_INTER);
  if (sr != NULL) 
    {
      debug(sr);
      return(-1);
    }

  return(0);
}
#endif /* CRAY */
