/*

ssh.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar 18 16:36:11 1995 ylo
Last modified: Wed Jul 12 01:29:21 1995 ylo

Ssh client program.  This program can be used to log into a remote machine.
The software supports strong authentication, encryption, and forwarding
of X11, TCP/IP, and authentication connections.

*/

#include "includes.h"
#include "xmalloc.h"
#include "randoms.h"
#include "ssh.h"
#include "packet.h"
#include "buffer.h"
#include "version.h"
#include "authfd.h"
#include "readconf.h"

/* Random number generator state.  This is initialized in ssh_login, and
   left initialized.  This is used both by the packet module and by various
   other functions. */
RandomState random_state;

/* Flag indicating whether debug mode is on.  This can be set on the
   command line. */
int debug_flag = 0;

/* Flag indicating whether to allocate a pseudo tty.  This can be set on the
   command line, and is automatically set if no command is given on the command
   line. */
int tty_flag = 0;

/* Flag indicating that nothing should be read from stdin.  This can be set
   on the command line. */
int stdin_null_flag = 0;

/* Flag indicating that ssh should fork after authentication.  This is useful
   so that the pasphrase can be entered manually, and then ssh goes to the
   background. */
int fork_after_authentication_flag = 0;

/* General data structure for command line options and options configurable
   in configuration files.  See readconf.h. */
Options options;

/* Name of the host we are connecting to.  This is the name given on the
   command line, or the HostName specified for the user-supplied name
   in a configuration file. */
char *host;

/* Flag to indicate that we have received a window change signal which has
   not yet been processed.  This will cause a message indicating the new
   window size to be sent to the server a little later.  This is volatile
   because this is updated in a signal handler. */
volatile int received_window_change_signal = 0;

/* Value of argv[0] (set in the main program). */
char *av0;

/* Flag indicating whether we have a valid host private key loaded. */
int host_private_key_loaded = 0;

/* Host private key. */
RSAPrivateKey host_private_key;


/* This function implements the interactive session, and is defined in this
   file. */
int do_session(int have_pty, int escape_char);

/* Terminal modes, as saved by enter_raw_mode. */
#ifdef USING_TERMIOS
struct termios saved_tio;
#endif
#ifdef USING_SGTTY
struct sgttyb saved_tio;
#endif

/* Flag indicating whether we are in raw mode.  This is used by enter_raw_mode
   and leave_raw_mode. */
int in_raw_mode = 0;

/* Flag indicating whether the user\'s terminal is in non-blocking mode. */
int in_non_blocking_mode = 0;

/* Puts the user\'s terminal in raw mode. */

void enter_raw_mode()
{
#ifdef USING_TERMIOS
  struct termios tio;

  if (tcgetattr(fileno(stdin), &tio) < 0)
    perror("tcgetattr");
  saved_tio = tio;
  tio.c_iflag |= IGNPAR;
  tio.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
  tio.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL);
  tio.c_oflag &= ~OPOST;
  tio.c_cc[VMIN] = 1;
  tio.c_cc[VTIME] = 0;
  if (tcsetattr(fileno(stdin), TCSADRAIN, &tio) < 0)
    perror("tcsetattr");
  in_raw_mode = 1;
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  struct sgttyb tio;

  if (ioctl(fileno(stdin), TIOCGETP, &tio) < 0)
    perror("ioctl(stdin, TIOCGETP, ...)");
  saved_tio = tio;
  tio.sg_flags &= ~(CBREAK | ECHO | CRMOD | LCASE | TANDEM);
  tio.sg_flags |= (RAW | ANYP);
  if (ioctl(fileno(stdin), TIOCSETP, &tio) < 0)
    perror("ioctl(stdin, TIOCSETP, ...)");
  in_raw_mode = 1;
#endif /* USING_SGTTY */
}  

/* Returns the user\'s terminal to normal mode if it had been put in raw 
   mode. */

void leave_raw_mode()
{
  if (!in_raw_mode)
    return;
  in_raw_mode = 0;
#ifdef USING_TERMIOS
  if (tcsetattr(fileno(stdin), TCSADRAIN, &saved_tio) < 0)
    perror("tcsetattr");
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  if (ioctl(fileno(stdin), TIOCSETP, &saved_tio) < 0)
    perror("ioctl(stdin, TIOCSETP, ...)");
#endif /* USING_SGTTY */
}

/* Puts stdin terminal in non-blocking mode. */

void enter_non_blocking()
{
  in_non_blocking_mode = 1;
#ifdef O_NONBLOCK
  (void)fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK */
  (void)fcntl(fileno(stdin), F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK */  
}

/* Restores stdin to blocking mode. */

void leave_non_blocking()
{
  (void)fcntl(fileno(stdin), F_SETFL, 0);
  in_non_blocking_mode = 0;
}

/* Signal handler for the window change signal (SIGWINCH).  This just
   sets a flag indicating that the window has changed. */

RETSIGTYPE window_change_handler(int sig)
{
  received_window_change_signal = 1;
  signal(SIGWINCH, window_change_handler);
}

/* Signal handler for signals that cause the program to terminate.  These
   signals must be trapped to restore terminal modes. */

RETSIGTYPE signal_handler(int sig)
{
  if (in_raw_mode)
    leave_raw_mode();
  if (in_non_blocking_mode)
    leave_non_blocking();
  channel_stop_listening();
  packet_close();
  fatal("Killed by signal %d.", sig);
}

/* Function to display an error message and exit.  This is in this file because
   this needs to restore terminal modes before exiting.  See log-client.c
   for other related functions. */

void fatal(const char *fmt, ...)
{
  va_list args;
  if (in_non_blocking_mode)
    leave_non_blocking();
  if (in_raw_mode)
    leave_raw_mode();
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  channel_stop_listening();
  packet_close();
  exit(255);
}

/* Prints a help message to the user.  This function never returns. */

void usage()
{
  fprintf(stderr, "Usage: %s [options] host [command]\n", av0);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -l user     Log in using this user name.\n");
  fprintf(stderr, "  -n          Redirect input from /dev/null.\n");
  fprintf(stderr, "  -a          Disable authentication agent forwarding.\n");
  fprintf(stderr, "  -x          Disable X11 connection forwarding.\n");
  fprintf(stderr, "  -i file     Identity for RSA authentication (default: ~/.ssh_identity).\n");
  fprintf(stderr, "  -t          Tty; allocate a tty even if command is given.\n");
  fprintf(stderr, "  -v          Verbose; display verbose debugging messages.\n");
  fprintf(stderr, "  -f          Fork into background after authentication.\n");
  fprintf(stderr, "  -e char     Set escape character; ``none'' = disable (default: ~).\n");
  fprintf(stderr, "  -c cipher   Select encryption algorithm: ``idea'' (default, secure),\n");
  fprintf(stderr, "              ``des'', ``3des'', ``tss'', ``rc4'' (fast, suitable for bulk\n");
  fprintf(stderr, "              transfers), ``none'' (no encryption).\n");
  fprintf(stderr, "  -p port     Connect to this port.  Server must be on the same port.\n");
  fprintf(stderr, "  -L listen-port:host:port   Forward local port to remote address\n");
  fprintf(stderr, "  -R listen-port:host:port   Forward remote port to local address\n");
  fprintf(stderr, "              These cause %s to listen for connections on a port, and\n", av0);
  fprintf(stderr, "              forward them to the other side by connecting to host:port.\n");
  fprintf(stderr, "  -o 'option' Process the option as if it was read from a configuration file.\n");
  exit(1);
}

/* Connects to the given host using rsh (or prints an error message and exits
   if rsh is not available).  This function never returns. */

void rsh_connect(char *host, char *user, Buffer *command)
{
#ifdef RSH_PATH
  char *args[10];
  int i;
  
  log("Using rsh.  WARNING: Connection will not be encrypted.");
  /* Build argument list for rsh. */
  i = 0;
  args[i++] = RSH_PATH;
  if (user)
    {
      args[i++] = "-l";
      args[i++] = user;
    }
  args[i++] = host;
  if (buffer_len(command) > 0)
    {
      buffer_append(command, "\0", 1);
      args[i++] = buffer_ptr(command);
    }
  args[i++] = NULL;
  execv(RSH_PATH, args);
  perror(RSH_PATH);
  exit(1);
#else /* RSH_PATH */
  fatal("Rsh not available.");
#endif /* RSH_PATH */
}

/* Main program for the ssh client. */

int main(int ac, char **av)
{
  int i, opt, optind, type, exit_status, sock, fwd_port, fwd_host_port, authfd;
  char *optarg, *cp, buf[256];
  Buffer command;
  struct winsize ws;
  struct stat st;
  struct passwd *pw;
  int interactive = 0, dummy;
  
  /* Save our own name. */
  av0 = av[0];

  /* Set RSA (actually gmp) memory allocation functions. */
  rsa_set_mp_memory_allocation();

  /* Initialize option structure to indicate that no values have been set. */
  initialize_options(&options);

  /* Parse command-line arguments. */
  host = NULL;
  
  for (optind = 1; optind < ac; optind++)
    {
      if (av[optind][0] != '-')
	{
	  if (host)
	    break;
	  host = av[optind];
	  continue;
	}
      opt = av[optind][1];
      if (!opt)
	usage();
      if (strchr("eilcpLRo", opt)) /* options with arguments */
	{
	  optarg = av[optind] + 2;
	  if (strcmp(optarg, "") == 0)
	    {
	      if (optind >= ac - 1)
		usage();
	      optarg = av[++optind];
	    }
	}
      else
	{
	  if (av[optind][2])
	    usage();
	  optarg = NULL;
	}
      switch (opt)
	{
	case 'n':
	  stdin_null_flag = 1;
	  break;

	case 'f':
	  fork_after_authentication_flag = 1;
	  stdin_null_flag = 1;
	  break;

	case 'x':
	  options.forward_x11 = 0;
	  break;

	case 'a':
	  options.forward_agent = 0;
	  break;

	case 'i':
	  if (stat(optarg, &st) < 0)
	    {
	      fprintf(stderr, "Warning: Identity file %s does not exist.\n",
		      optarg);
	      break;
	    }
	  if (options.num_identity_files >= SSH_MAX_IDENTITY_FILES)
	    fatal("Too many identity files specified (max %d)",
		  SSH_MAX_IDENTITY_FILES);
	  options.identity_files[options.num_identity_files++] = 
	    xstrdup(optarg);
	  break;

	case 't':
	  tty_flag = 1;
	  break;

	case 'v':
	  debug_flag = 1;
	  fprintf(stderr, "SSH Version %s, protocol version %d.%d.\n",
		  SSH_VERSION, PROTOCOL_MAJOR, PROTOCOL_MINOR);
#ifdef RSAREF
	  fprintf(stderr, "Compiled with RSAREF.\n");
#else /* RSAREF */
	  fprintf(stderr, "International version.  Does not use RSAREF.\n");
#endif /* RSAREF */
	  break;

	case 'e':
	  if (optarg[0] == '^' && optarg[2] == 0 &&
	      (unsigned char)optarg[1] >= 64 && (unsigned char)optarg[1] < 128)
	    options.escape_char = (unsigned char)optarg[1] & 31;
	  else
	    if (strlen(optarg) == 1)
	      options.escape_char = (unsigned char)optarg[0];
	    else
	      if (strcmp(optarg, "none") == 0)
		options.escape_char = -2;
	      else
		{
		  fprintf(stderr, "Bad escape character '%s'.\n", optarg);
		  exit(1);
		}
	  break;

	case 'c':
	  options.cipher = cipher_number(optarg);
	  if (options.cipher == -1)
	    {
	      fprintf(stderr, "Unknown cipher type '%s'\n", optarg);
	      exit(1);
	    }
	  break;

	case 'p':
	  options.port = atoi(optarg);
	  if (options.port < 1 || options.port > 65535)
	    {
	      fprintf(stderr, "Bad port %s.\n", optarg);
	      exit(1);
	    }
	  break;

	case 'l':
	  options.user = optarg;
	  break;

	case 'R':
	  if (sscanf(optarg, "%d:%255[^:]:%d", &fwd_port, buf, 
		     &fwd_host_port) != 3)
	    {
	      fprintf(stderr, "Bad forwarding specification '%s'.\n", optarg);
	      usage();
	      /*NOTREACHED*/
	    }
	  if (fwd_port < 1024 && getuid() != 0)
	    {
	      fprintf(stderr, 
		      "Privileged ports can only be forwarded by root.\n");
	      exit(1);
	    }
	  add_remote_forward(&options, fwd_port, buf, fwd_host_port);
	  break;

	case 'L':
	  if (sscanf(optarg, "%d:%255[^:]:%d", &fwd_port, buf, 
		     &fwd_host_port) != 3)
	    {
	      fprintf(stderr, "Bad forwarding specification '%s'.\n", optarg);
	      usage();
	      /*NOTREACHED*/
	    }
	  if (fwd_port < 1024 && getuid() != 0)
	    {
	      fprintf(stderr, 
		      "Privileged ports can only be forwarded by root.\n");
	      exit(1);
	    }
	  add_local_forward(&options, fwd_port, buf, fwd_host_port);
	  break;

	case 'o':
	  dummy = 1;
	  process_config_line(&options, host ? host : "", optarg,
			      "command-line", 0, &dummy);
	  break;

	default:
	  usage();
	}
    }

 /* Check that we got a host name. */
  if (!host)
    usage();

  /* Initialize the command to execute on remote host. */
  buffer_init(&command);

  /* Save the command to execute on the remote host in a buffer.  There is
     no limit on the length of the command, except by the maximum packet
     size.  Also sets the tty flag if there is no command. */
  if (optind == ac)
    {
      /* No command specified - execute shell on a tty. */
      tty_flag = 1;
    }
  else
    {
      /* A command has been specified.  Store it into the buffer. */
      for (i = optind; i < ac; i++)
	{
	  if (i > optind)
	    buffer_append(&command, " ", 1);
	  buffer_append(&command, av[i], strlen(av[i]));
	}
    }

  /* Cannot fork to background if no command. */
  if (fork_after_authentication_flag && buffer_len(&command) == 0)
    fatal("Cannot fork into background without a command to execute.");
  
  /* Allocate a tty by default if no command specified. */
  if (buffer_len(&command) == 0)
    tty_flag = 1;

  /* Do not allocate a tty if stdin is not a tty. */
  if (!isatty(fileno(stdin)))
    {
      if (tty_flag)
	log("Pseudo-terminal will not be allocated because stdin is not a terminal.");
      tty_flag = 0;
    }

  /* Initialize "log" output.  Since we are the client all output actually
     goes to the terminal. */
  log_init(av[0], 1, debug_flag, 0);

  /* Get user data. */
  pw = getpwuid(getuid());

  /* Read per-user configuration file. */
  sprintf(buf, "%s/%s", pw->pw_dir, SSH_USER_CONFFILE);
  read_config_file(buf, host, &options);

  /* Read systemwide configuration file. */
  read_config_file(HOST_CONFIG_FILE, host, &options);

  /* Fill configuration defaults. */
  fill_default_options(&options);
  if (options.user == NULL)
    options.user = xstrdup(pw->pw_name);

  if (options.hostname != NULL)
    host = options.hostname;

  /* Disable rhosts authentication if not running as root. */
  if (geteuid() != 0)
    {
      options.rhosts_authentication = 0;
      options.rhosts_rsa_authentication = 0;
    }

  /* If using rsh has been selected, exec it now (without trying anything
     else).  Note that we must release privileges first. */
  if (options.use_rsh)
    {
      /* Drop extra privileges before executing rsh. */
      setgid(getgid());
      setuid(getuid());
      rsh_connect(host, options.user, &command);
      fatal("rsh_connect returned");
    }

  /* Open a connection to the remote host.  This needs root privileges if
     rhosts_authentication is true. */
  sock = ssh_connect(host, options.port, 
		     !options.rhosts_authentication &&
		     !options.rhosts_rsa_authentication);

  /* If we successfully made the connection, load the host private key in
     case we will need it later for combined rsa-rhosts authentication. 
     This must be done before releasing extra privileges, because the file
     is only readable by root. */
  if (sock != -1)
    {
      if (load_private_key(HOST_KEY_FILE, "", &host_private_key, NULL))
	host_private_key_loaded = 1;
    }

  /* Get rid of any extra privileges that we may have.  We will no longer need
     them.  Also, extra privileges could make it very hard to read identity
     files and other non-world-readable files from the user\'s home directory
     if it happens to be on a NFS volume where root is mapped to nobody. */
  setgid(getgid());
  setuid(getuid());

  /* Now that we are back to our own permissions, create ~/.ssh directory
     if it doesn\'t already exist. */
  sprintf(buf, "%s/%s", pw->pw_dir, SSH_USER_DIR);
  if (stat(buf, &st) < 0)
    if (mkdir(buf, 0755) < 0)
      error("Could not create directory '%.200s'.", buf);

  /* Check if the connection failed, and try "rsh" if appropriate. */
  if (sock == -1)
    {
      if (options.port != 0)
	log("Connection to %.100s on port %d was refused.", 
	    host, options.port);
      else
	log("Connection to %.100s was refused.", host);

      if (options.fallback_to_rsh)
	{
	  rsh_connect(host, options.user, &command);
	  fatal("rsh_connect returned");
	}
      exit(1);
    }

  /* Expand ~ in options.identity_files.   Warning: tilde_expand_filename
     corrupts pw. */
  for (i = 0; i < options.num_identity_files; i++)
    options.identity_files[i] = 
      tilde_expand_filename(options.identity_files[i], getuid());

  /* Log into the remote system.  This never returns if the login fails. 
     Note: this initializes the random state, and leaves it initialized. */
  ssh_login(&random_state, host_private_key_loaded, &host_private_key, 
	    sock, host, options.user, options.num_identity_files,
	    options.identity_files,
	    options.rhosts_authentication, options.rhosts_rsa_authentication,
	    options.rsa_authentication,
	    options.password_authentication, options.cipher);

  /* We no longer need the host private key.  Clear it now. */
  if (host_private_key_loaded)
    rsa_clear_private_key(&host_private_key);

  /* If requested, fork and let ssh continue in the background. */
  if (fork_after_authentication_flag)
    {
      int ret = fork();
      if (ret == -1)
	fatal("fork failed: %s", strerror(errno));
      if (ret != 0)
	exit(0);
#ifdef HAVE_SETSID
      setsid();
#endif /* HAVE_SETSID */
    }

  /* Allocate a pseudo tty if appropriate. */
  if (tty_flag)
    {
      debug("Requesting pty.");

      /* Start the packet. */
      packet_start(SSH_CMSG_REQUEST_PTY);

      /* Store TERM in the packet.  There is no limit on the length of the
         string. */
      cp = getenv("TERM");
      if (!cp)
	cp = "";
      packet_put_string(cp, strlen(cp));

      /* Store window size in the packet. */
      if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) < 0)
	memset(&ws, 0, sizeof(ws));
      packet_put_int(ws.ws_row);
      packet_put_int(ws.ws_col);
      packet_put_int(ws.ws_xpixel);
      packet_put_int(ws.ws_ypixel);
      
      /* Store tty modes in the packet. */
      tty_make_modes(fileno(stdin));

      /* Send the packet, and wait for it to leave. */
      packet_send();
      packet_write_wait();

      /* Read response from the server. */
      type = packet_read();
      if (type == SSH_SMSG_SUCCESS)
	interactive = 1;
      else
	log("Warning: Remote host failed or refused to allocate a pseudo tty.");
    }

  /* Request X11 forwarding if enabled and DISPLAY is set. */
  if (options.forward_x11 && getenv("DISPLAY") != NULL)
    {
      char line[512], proto[512], data[512];
      FILE *f;
      int forwarded = 0;

      /* Try to get Xauthority information for the display. */
      sprintf(line, "%s list %.200s 2>/dev/null", 
	      XAUTH_PATH, getenv("DISPLAY"));
      f = popen(line, "r");
      if (f && fgets(line, sizeof(line), f) && 
	  sscanf(line, "%*s %s %s", proto, data) == 2)
	{
	  /* Got Reasonable information.  Request forwarding with
	     authentication spoofing. */
	  debug("Requesting X11 connection forwarding with authentication spoofing.");
	  x11_request_forwarding_with_spoofing(&random_state, proto, data);

	  /* Read response from the server. */
	  type = packet_read();
	  if (type == SSH_SMSG_SUCCESS)
	    {
	      forwarded = 1;
	      interactive = 1;
	    }

	  else
	    log("Warning: Remote host denied X11 authentication spoofing.");
	}
      if (f)
	pclose(f);

      if (!forwarded)
	{
	  /* We were unable to obtain Xauthority data.  Just forward the
	     connection, but only use a unix domain socket for security
	     reasons.  The user should have "xhost localhost" done (or for
	     whatever host the user is running the client from). */
	  debug("Requesting X11 connection forwarding for unix domain socket.");
	  x11_request_forwarding();

	  /* Read response from the server. */
	  type = packet_read();
	  if (type == SSH_SMSG_SUCCESS)
	    interactive = 1;
	  else
	    log("Warning: Remote host denied X11 forwarding.");
	}
    }

  /* Tell the packet module whether this is an interactive session. */
  packet_set_interactive(interactive);

  /* Clear agent forwarding if we don\'t have an agent. */
  authfd = ssh_get_authentication_fd();
  if (authfd < 0)
    options.forward_agent = 0;
  else
    ssh_close_authentication_socket(authfd);

  /* Request authentication agent forwarding if appropriate. */
  if (options.forward_agent)
    {
      debug("Requesting authentication agent forwarding.");
      auth_request_forwarding();
      
      /* Read response from the server. */
      type = packet_read();
      if (type != SSH_SMSG_SUCCESS)
	log("Warning: Remote host denied authentication agent forwarding.");
    }

  /* Initiate local TCP/IP port forwardings. */
  for (i = 0; i < options.num_local_forwards; i++)
    {
      debug("Connections to local port %d forwarded to remote address %.200s:%d",
	    options.local_forwards[i].port, options.local_forwards[i].host, 
	    options.local_forwards[i].host_port);
      channel_request_local_forwarding(options.local_forwards[i].port,
				       options.local_forwards[i].host,
				       options.local_forwards[i].host_port);
    }

  /* Initiate remote TCP/IP port forwardings. */
  for (i = 0; i < options.num_remote_forwards; i++)
    {
      debug("Connections to remote port %d forwarded to local address %.200s:%d",
	    options.remote_forwards[i].port, options.remote_forwards[i].host, 
	    options.remote_forwards[i].host_port);
      channel_request_remote_forwarding(options.remote_forwards[i].port,
					options.remote_forwards[i].host,
					options.remote_forwards[i].host_port);
    }

  /* If a command was specified on the command line, execute the command now.
     Otherwise request the server to start a shell. */
  if (buffer_len(&command) > 0)
    {
      int len = buffer_len(&command);
      if (len > 900)
	len = 900;
      debug("Sending command: %.*s", len, buffer_ptr(&command));
      packet_start(SSH_CMSG_EXEC_CMD);
      packet_put_string(buffer_ptr(&command), buffer_len(&command));
      packet_send();
      packet_write_wait();
    }
  else
    {
      debug("Requesting shell.");
      packet_start(SSH_CMSG_EXEC_SHELL);
      packet_send();
      packet_write_wait();
    }

  /* Set signal handlers to restore non-blocking mode.  */
  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Enter the session. */
  if (tty_flag)
    {
      /* We have a tty. */
#ifdef SIGWINCH
      signal(SIGWINCH, window_change_handler);
#endif /* SIGWINCH */
      exit_status = do_session(1, options.escape_char);
#ifdef SIGWINCH
      signal(SIGWINCH, SIG_DFL);
#endif /* SIGWINCH */
    }
  else
    {
      /* There is no tty. */
      exit_status = do_session(0, -1);
    }

  /* Close the connection to the remote host. */
  packet_close();
  
  /* Exit with the status returned by the program on the remote side. */
  exit(exit_status);
}

/* Returns current time in seconds from Jan 1, 1970 with the maximum available
   resolution. */

double get_current_time()
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
#else /* HAVE_GETTIMEOFDAY */
  return (double)time(NULL);
#endif /* HAVE_GETTIMEOFDAY */
}

/* Implements the interactive session with the server.  This is called
   after the user has been authenticated, and a command has been
   started on the remote host.  If escape_char != -1, it is the character
   used as an escape character for terminating or suspending the
   session. */

int do_session(int have_pty, int escape_char)
{
  int escape_pending = 0;  /* Last character was the escape character */
  int last_was_cr = 1; /* Last character was a newline. */
  int exit_status = -1; /* Used to store the exit status of the command. */
  int stdin_eof = 0; /* EOF has been encountered on standard error. */
  Buffer stdin_buffer;  /* Buffer for stdin data. */
  Buffer stdout_buffer; /* Buffer for stdout data. */
  Buffer stderr_buffer; /* Buffer for stderr data. */
  const unsigned int buffer_high = 64*1024; /* Soft max buffer size. */
  int max_fd; /* Maximum file descriptor number in select(). */
  int connection = packet_get_connection(); /* Connection to server. */
  int type, len;
  char buf[32768];
  char *data;
  unsigned int data_len;
  unsigned long stdin_bytes = 0, stdout_bytes = 0, stderr_bytes = 0;
  double start_time, total_time;

  debug("Entering interactive session.");

  start_time = get_current_time();

  /* Initialize maximum file descriptor. */
  max_fd = connection;

  /* Enter raw mode if have a pseudo terminal. */
  if (have_pty)
    enter_raw_mode();

  /* Initialize buffers. */
  buffer_init(&stdin_buffer);
  buffer_init(&stdout_buffer);
  buffer_init(&stderr_buffer);

  /* If standard input is to be "redirected from /dev/null", we simply
     mark that we have seen an EOF and send an EOF message to the server.
     Otherwise, we try to read a single character; it appears that for some
     files, such /dev/null, select() never wakes up for read for this
     descriptor, which means that we never get EOF.  This way we will get
     the EOF if stdin comes from /dev/null or similar. */
  if (stdin_null_flag)
    {
      /* Fake EOF on stdin. */
      debug("Sending eof.");
      stdin_eof = 1;
      packet_start(SSH_CMSG_EOF);
      packet_send();
    }
  else
    {
      /* Enter non-blocking mode for stdin. */
      enter_non_blocking();

      /* Check for immediate EOF on stdin. */
      len = read(fileno(stdin), buf, 1);
      if (len == 0)
	{
	  /* EOF.  Record that we have seen it and send EOF to server. */
	  debug("Sending eof.");
	  stdin_eof = 1;
	  packet_start(SSH_CMSG_EOF);
	  packet_send();
	}
      else
	if (len > 0)
	  {
	    /* Got data.  We must store the data in the buffer, and also
	       process it as an escape character if appropriate. */
	    if ((unsigned char)buf[0] == escape_char)
	      escape_pending = 1;
	    else
	      {
		buffer_append(&stdin_buffer, buf, 1);
		stdin_bytes += 1;
	      }
	  }
      
      /* Leave non-blocking mode. */
      leave_non_blocking();
    }

  /* We stay in this loop until one of the following happens:
       - we receive SSH_SMSG_EXITSTATUS
       - the user types <newline>~. (and we have escape character)
       - server closes the connection
       - an error reported via fatal() causes the program to terminate
       - select fails.

     The loop is organized as follows:
       1. Process any buffered packets from the server.
       2. Send buffered stdin data to the server.
       3. Send channel data to the server.
       4. Send possible window change message to the server.
       5. Initialize select masks.
       6. Sleep in select().
       7. Do operations for channels.
       8. Read input from the server (store in buffer).
       9. Read input from stdin (store in buffer).
       10. Write buffered output to stdout.
       11. Write buffered output to stderr.
       12. Send buffered packet data to the server.
     After the loop there is cleanup and termination code. */

  for (;;)
    {
      fd_set readset, writeset;

      /* Process any buffered packets from the server. */
      while ((type = packet_read_poll()) != SSH_MSG_NONE)
	{
	  switch (type)
	    {

	    case SSH_SMSG_STDOUT_DATA:
	      data = packet_get_string(&data_len);
	      buffer_append(&stdout_buffer, data, data_len);
	      stdout_bytes += data_len;
	      memset(data, 0, data_len);
	      xfree(data);
	      break;

	    case SSH_SMSG_STDERR_DATA:
	      data = packet_get_string(&data_len);
	      buffer_append(&stderr_buffer, data, data_len);
	      stdout_bytes += data_len;
	      memset(data, 0, data_len);
	      xfree(data);
	      break;

	    case SSH_SMSG_EXITSTATUS:
	      exit_status = packet_get_int();
	      /* Acknowledge the exit. */
	      packet_start(SSH_CMSG_EXIT_CONFIRMATION);
	      packet_send();
	      /* Must wait for packet to be sent since we are exiting the
		 loop. */
	      packet_write_wait();
	      /* Go close the connection. */
	      goto quit;

	    case SSH_SMSG_X11_OPEN:
	      x11_input_open();
	      break;

	    case SSH_MSG_PORT_OPEN:
	      channel_input_port_open();
	      break;

	    case SSH_SMSG_AGENT_OPEN:
	      auth_input_open_request();
	      break;

	    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
	      channel_input_open_confirmation();
	      break;

	    case SSH_MSG_CHANNEL_OPEN_FAILURE:
	      channel_input_open_failure();
	      break;

	    case SSH_MSG_CHANNEL_DATA:
	      channel_input_data();
	      break;

	    case SSH_MSG_CHANNEL_CLOSE:
	      channel_input_close();
	      break;

	    case SSH_MSG_CHANNEL_CLOSE_CONFIRMATION:
	      channel_input_close_confirmation();
	      break;

	    default:
	      /* Any unknown packets received during the actual session
		 cause the session to terminate.  This is intended to make
		 debugging easier since no confirmations are sent.  Any
		 compatible protocol extensions must be negotiated during
		 the preparatory phase. */
	      packet_disconnect("Protocol error during session: type %d",
				type);
	    }
	}

      /* Send buffered stdin data to the server. */
      while (buffer_len(&stdin_buffer) > 0 && 
	     packet_not_very_much_data_to_write())
	{
	  len = buffer_len(&stdin_buffer);
	  if (len > 32768)
	    len = 32768;  /* Keep the packets at reasonable size. */
	  packet_start(SSH_CMSG_STDIN_DATA);
	  packet_put_string(buffer_ptr(&stdin_buffer), len);
	  packet_send();
	  buffer_consume(&stdin_buffer, len);
	  /* If we have a pending EOF, send it now. */
	  if (stdin_eof && buffer_len(&stdin_buffer) == 0)
	    {
	      packet_start(SSH_CMSG_EOF);
	      packet_send();
	    }
	}

      /* Send channel data to the server. */
      if (packet_not_very_much_data_to_write())
	channel_output_poll();

#ifdef SIGWINCH
      /* Send possible window change message to the server. */
      if (received_window_change_signal)
	{
	  struct winsize ws;
	  /* Clear the window change indicator. */
	  received_window_change_signal = 0;
	  /* Read new window size. */
	  if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0)
	    {
	      /* Successful, send the packet now. */
	      packet_start(SSH_CMSG_WINDOW_SIZE);
	      packet_put_int(ws.ws_row);
	      packet_put_int(ws.ws_col);
	      packet_put_int(ws.ws_xpixel);
	      packet_put_int(ws.ws_ypixel);
	      packet_send();
	    }
	}
#endif /* SIGWINCH */
	    
      /* Initialize select masks. */
      FD_ZERO(&readset);

      /* Read from the connection, unless our buffers are full. */
      if (buffer_len(&stdout_buffer) < buffer_high &&
	  buffer_len(&stderr_buffer) < buffer_high &&
	  channel_not_very_much_buffered_data())
	FD_SET(connection, &readset);

      /* Read from stdin, unless we have seen EOF or have very much buffered
	 data to send to the server. */
      if (!stdin_eof && packet_not_very_much_data_to_write())
	FD_SET(fileno(stdin), &readset);

      FD_ZERO(&writeset);

      /* Select server connection if have data to write to the server. */
      if (packet_have_data_to_write())
	FD_SET(connection, &writeset);

      /* Select stdout if have data in buffer. */
      if (buffer_len(&stdout_buffer) > 0)
	FD_SET(fileno(stdout), &writeset);

      /* Select stderr if have data in buffer. */
      if (buffer_len(&stderr_buffer) > 0)
	FD_SET(fileno(stderr), &writeset);
      
      /* Add any selections by the channel mechanism. */
      channel_prepare_select(&readset, &writeset);

      /* Update maximum file descriptor number, if appropriate. */
      if (channel_max_fd() > max_fd)
	max_fd = channel_max_fd();

      /* Wait for something to happen.  This will suspend the process until
	 some selected descriptor can be read, written, or has some other
	 event pending.  Note: if you want to implement SSH_MSG_IGNORE
	 messages to fool traffic analysis, this might be the place to do
	 it: just have a random timeout for the select, and send a random
	 SSH_MSG_IGNORE packet when the timeout expires. */
      if (select(max_fd + 1, &readset, &writeset, NULL, NULL) < 0)
	{
	  if (errno == EINTR)
	    continue;
	  /* Note: we might still have data in the buffers. */
	  sprintf(buf, "select: %s\r\n", strerror(errno));
	  buffer_append(&stderr_buffer, buf, strlen(buf));
	  stderr_bytes += strlen(buf);
	  goto quit;
	}

      /* Do channel operations. */
      channel_after_select(&readset, &writeset);

      /* Read input from the server, and add any such data to the buffer of the
	 packet subsystem. */
      if (FD_ISSET(connection, &readset))
	{
	  /* Read as much as possible. */
	  len = read(connection, buf, sizeof(buf));
	  if (len == 0)
	    { 
	      /* Received EOF.  The remote host has closed the connection. */
	      sprintf(buf, "Connection to %.300s closed by remote host.\r\n",
		      host);
	      buffer_append(&stderr_buffer, buf, strlen(buf));
	      stderr_bytes += strlen(buf);
	      goto quit;
	    }
	  if (len < 0)
	    {
	      /* An error has encountered.  Perhaps there is a network
		 problem. */
	      sprintf(buf, "Read from remote host %.300s: %s\r\n", 
		      host, strerror(errno));
	      buffer_append(&stderr_buffer, buf, strlen(buf));
	      stderr_bytes += strlen(buf);
	      goto quit;
	    }
	  packet_process_incoming(buf, len);
	}

      /* Read input from stdin. */
      if (FD_ISSET(fileno(stdin), &readset))
	{
	  /* Read as much as possible. */
	  len = read(fileno(stdin), buf, sizeof(buf));
	  if (len <= 0)
	    {
	      /* Received EOF or error.  They are treated similarly,
		 except that an error message is printed if it was
		 an error condition. */
	      if (len < 0)
		{
		  sprintf(buf, "read: %s\r\n", strerror(errno));
		  buffer_append(&stderr_buffer, buf, strlen(buf));
		  stderr_bytes += strlen(buf);
		}
	      /* Mark that we have seen EOF. */
	      stdin_eof = 1;
	      /* Send an EOF message to the server unless there is data
		 in the buffer.  If there is data in the buffer, no message
		 will be sent now.  Code elsewhere will send the EOF
		 when the buffer becomes empty if stdin_eof is set. */
	      if (buffer_len(&stdin_buffer) == 0)
		{
		  packet_start(SSH_CMSG_EOF);
		  packet_send();
		}
	    }
	  else
	    if (escape_char == -1)
	      {
		/* Normal successful read, and no escape character.  Just 
		   append the data to buffer. */
		buffer_append(&stdin_buffer, buf, len);
		stdin_bytes += len;
	      }
	    else
	      {
		/* Normal, successful read.  But we have an escape character
		   and have to process the characters one by one. */
		unsigned int i;
		for (i = 0; i < len; i++)
		  {
		    unsigned char ch;
		    /* Get one character at a time. */
		    ch = buf[i];

		    if (escape_pending)
		      {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			escape_pending = 0;
			/* Process the escaped character. */
			if (ch == '.')
			  {
			    /* Terminate the connection. */
			    sprintf(buf, "%c.\r\n", escape_char);
			    buffer_append(&stderr_buffer, buf, strlen(buf));
			    stderr_bytes += strlen(buf);
			    goto quit;
			  }
			else
			  if (ch == 'Z' - 64)
			    {
			      /* Suspend the program. */
			      /* Print a message to that effect to the user. */
			      sprintf(buf, "%c^Z\r\n", escape_char);
			      buffer_append(&stderr_buffer, buf, strlen(buf));
			      stderr_bytes += strlen(buf);

			      /* Flush stdout and stderr buffers. */
			      if (buffer_len(&stdout_buffer) > 0)
				write(fileno(stdout), 
				      buffer_ptr(&stdout_buffer), 
				      buffer_len(&stdout_buffer));
			      if (buffer_len(&stderr_buffer) > 0)
				write(fileno(stderr), 
				      buffer_ptr(&stderr_buffer), 
				      buffer_len(&stderr_buffer));
			      /* Leave raw mode. */
			      leave_raw_mode();
			      /* Free (and clear) the buffer to reduce the
				 amount of data that gets written to swap. */
			      buffer_free(&stdin_buffer);
			      buffer_free(&stdout_buffer);
			      buffer_free(&stderr_buffer);
			      memset(buf, 0, sizeof(buf));
			      /* Send the suspend signal to the program
				 itself. */
			      kill(getpid(), SIGTSTP);
			      /* OK, we have been continued by the user. 
			         Reinitialize buffers. */
			      buffer_init(&stdin_buffer);
			      buffer_init(&stdout_buffer);
			      buffer_init(&stderr_buffer);
			      /* Re-enter raw mode. */
			      enter_raw_mode();
			      continue;
			    }
			  else
			    if (ch != escape_char)
			      {
				/* Escape character followed by non-special
				   character.  Append both to the input
				   buffer. */
				buf[0] = escape_char;
				buf[1] = ch;
				buffer_append(&stdin_buffer, buf, 2);
				stdin_bytes += 2;
				continue;
			      }
			/* Note that escape character typed twice falls through
			   here; the latter gets processed as a normal
			   character below. */
		      }
		    else
		      {
			/* The previous character was not an escape char. 
			   Check if this is an escape. */
			if (last_was_cr && ch == escape_char)
			  {
			    /* It is. Set the flag and continue to next
			       character. */
			    escape_pending = 1;
			    continue;
			  }
		      }
		    /* Normal character.  Record whether it was a newline,
		       and append it to the buffer. */
		    last_was_cr = (ch == '\r' || ch == '\n');
		    buf[0] = ch;
		    buffer_append(&stdin_buffer, buf, 1);
		    stdin_bytes += 1;
		    continue;
		  }
	      }
	}

      /* Write buffered output to stdout. */
      if (FD_ISSET(fileno(stdout), &writeset))
	{
	  /* Write as much data as possible. */
	  len = write(fileno(stdout), buffer_ptr(&stdout_buffer),
		      buffer_len(&stdout_buffer));
	  if (len <= 0)
	    {
	      if (errno == EAGAIN)
		len = 0;
	      else
		{
		  /* An error or EOF was encountered.  Put an error message
		     to stderr buffer. */
		  sprintf(buf, "write stdout: %s\r\n", strerror(errno));
		  buffer_append(&stderr_buffer, buf, strlen(buf));
		  stderr_bytes += strlen(buf);
		  goto quit;
		}
	    }
	  /* Consume printed data from the buffer. */
	  buffer_consume(&stdout_buffer, len);
	}

      /* Write buffered output to stderr. */
      if (FD_ISSET(fileno(stderr), &writeset))
	{
	  /* Write as much data as possible. */
	  len = write(fileno(stderr), buffer_ptr(&stderr_buffer),
		      buffer_len(&stderr_buffer));
	  if (len <= 0)
	    if (errno == EAGAIN)
	      len = 0;
	    else
	      goto quit; /* EOF or error, but can't even print error message. */
	  /* Consume printed characters from the buffer. */
	  buffer_consume(&stderr_buffer, len);
	}

      /* Send as much buffered packet data as possible to the sender. */
      if (FD_ISSET(connection, &writeset))
	packet_write_poll();
    }

 quit:
  /* Terminate the session. */

  /* Stop listening for connections. */
  channel_stop_listening();

  /* In interactive mode (with pseudo tty) display a message indicating that
     the connection has been closed. */
  if (have_pty)
    {
      sprintf(buf, "Connection to %.300s closed.\r\n", host);
      buffer_append(&stderr_buffer, buf, strlen(buf));
      stderr_bytes += strlen(buf);
    }

  /* Output any buffered data for stdout. */
  while (buffer_len(&stdout_buffer) > 0)
    {
      len = write(fileno(stdout), buffer_ptr(&stdout_buffer), 
		  buffer_len(&stdout_buffer));
      if (len <= 0)
	{
	  error("Write failed flushing stdout buffer.");
	  break;
	}
      buffer_consume(&stdout_buffer, len);
    }

  /* Output any buffered data for stderr. */
  while (buffer_len(&stderr_buffer) > 0)
    {
      len = write(fileno(stderr), buffer_ptr(&stderr_buffer), 
		  buffer_len(&stderr_buffer));
      if (len <= 0)
	{
	  error("Write failed flushing stderr buffer.");
	  break;
	}
      buffer_consume(&stderr_buffer, len);
    }

  /* Leave raw mode. */
  if (have_pty)
    leave_raw_mode();

  /* Clear and free any buffers. */
  memset(buf, 0, sizeof(buf));
  buffer_free(&stdin_buffer);
  buffer_free(&stdout_buffer);
  buffer_free(&stderr_buffer);

  /* Report bytes transferred, and transfer rates. */
  total_time = get_current_time() - start_time;
  debug("Transferred: stdin %lu, stdout %lu, stderr %lu bytes in %.1f seconds",
	stdin_bytes, stdout_bytes, stderr_bytes, total_time);
  if (total_time > 0)
    debug("Bytes per second: stdin %.1f, stdout %.1f, stderr %.1f\n",
	  stdin_bytes / total_time, stdout_bytes / total_time,
	  stderr_bytes / total_time);

  /* Return the exit status of the program. */
  debug("Exit status %d", exit_status);
  return exit_status;
}
