/*

serverloop.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Sep 10 00:30:37 1995 ylo

Server main loop for handling the interactive session.

*/

/*
 * $Id: serverloop.c,v 1.16 1998/05/04 13:36:28 kivinen Exp $
 * $Log: serverloop.c,v $
 * Revision 1.16  1998/05/04 13:36:28  kivinen
 * 	Fixed no_port_forwarding_flag so that it will also disable
 * 	local port forwardings from the server side. Moved
 * 	packet_get_all after reading the the remote_channel number
 * 	from the packet.
 *
 * Revision 1.15  1998/03/27 17:01:02  kivinen
 * 	Fixed idle_time code.
 *
 * Revision 1.14  1997/04/21 01:04:46  kivinen
 * 	Changed server_loop to call pty_cleanup_proc instead of
 * 	pty_release, so we can be sure it is never called twice.
 *
 * Revision 1.13  1997/04/17 04:19:28  kivinen
 * 	Added ttyame argument to wait_until_can_do_something and
 * 	server_loop functions.
 * 	Release pty before closing it.
 *
 * Revision 1.12  1997/04/05 21:52:54  kivinen
 * 	Fixed closing of pty, and changed it to use shutdown first and
 * 	close the pty only after pty have been released.
 *
 * Revision 1.11  1997/03/26 07:16:11  kivinen
 * 	Fixed idle_time code.
 *
 * Revision 1.10  1997/03/26 05:28:18  kivinen
 * 	Added idle timeout support.
 *
 * Revision 1.9  1997/03/25 05:48:49  kivinen
 * 	Moved closing of sockets/pipes out from server_loop.
 *
 * Revision 1.8  1997/03/19 19:25:17  kivinen
 * 	Added input buffer clearing for error conditions, so packet.c
 * 	can check that buffer must be empty before new packet is read
 * 	in.
 *
 * Revision 1.7  1997/03/19 17:56:31  kivinen
 * 	Fixed sigchld race condition.
 *
 * Revision 1.6  1996/11/24 08:25:14  kivinen
 * 	Added SSHD_NO_PORT_FORWARDING support.
 * 	Changed all code that checked EAGAIN to check EWOULDBLOCK too.
 *
 * Revision 1.5  1996/09/29 13:42:55  ylo
 * 	Increased the time to wait for more data from 10 ms to 17 ms
 * 	and bytes to 512 (I'm worried it might not always be
 * 	working due to the delay being shorter than the systems
 * 	fundamental clock tick).
 *
 * Revision 1.4  1996/09/14 08:42:26  ylo
 * 	Added cvs logs.
 *
 * $EndLog$
 */

#include "includes.h"
#include "xmalloc.h"
#include "ssh.h"
#include "packet.h"
#include "buffer.h"
#include "servconf.h"
#include "pty.h"

/* Flags that may be set in authorized_keys options. */
extern int no_port_forwarding_flag;

extern time_t idle_timeout;
static time_t idle_time_last = 0;

static Buffer stdin_buffer;	/* Buffer for stdin data. */
static Buffer stdout_buffer;	/* Buffer for stdout data. */
static Buffer stderr_buffer;	/* Buffer for stderr data. */
static int fdin;		/* Descriptor for stdin (for writing) */
static int fdout;		/* Descriptor for stdout (for reading);
				   May be same number as fdin. */
static int fderr;		/* Descriptor for stderr.  May be -1. */
static long stdin_bytes = 0;	/* Number of bytes written to stdin. */
static long stdout_bytes = 0;	/* Number of stdout bytes sent to client. */
static long stderr_bytes = 0;	/* Number of stderr bytes sent to client. */
static long fdout_bytes = 0;	/* Number of stdout bytes read from program. */
static int stdin_eof = 0;	/* EOF message received from client. */
static int fdout_eof = 0;	/* EOF encountered reading from fdout. */
static int fderr_eof = 0;	/* EOF encountered readung from fderr. */
static int connection_in;	/* Connection to client (input). */
static int connection_out;	/* Connection to client (output). */
static unsigned int buffer_high;/* "Soft" max buffer size. */
static int max_fd;		/* Max file descriptor number for select(). */

/* This SIGCHLD kludge is used to detect when the child exits.  The server
   will exit after that, as soon as forwarded connections have terminated. */

static int child_pid;  			/* Pid of the child. */
static volatile int child_terminated;	/* The child has terminated. */
static volatile int child_wait_status;	/* Status from wait(). */
static int child_just_terminated;	/* No select() done after termin. */

RETSIGTYPE sigchld_handler(int sig)
{
  int wait_pid;
  debug("Received SIGCHLD.");
  wait_pid = wait((int *)&child_wait_status);
  if (wait_pid != -1)
    {
      if (wait_pid != child_pid)
	error("Strange, got SIGCHLD and wait returned pid %d but child is %d",
	      wait_pid, child_pid);
      if (WIFEXITED(child_wait_status) ||
	  WIFSIGNALED(child_wait_status))
	{
	  child_terminated = 1;
	  child_just_terminated = 1;
	}
    }
  signal(SIGCHLD, sigchld_handler);
}

/* Process any buffered packets that have been received from the client. */

void process_buffered_input_packets()
{
  int type;
  char *data;
  unsigned int data_len;
  int row, col, xpixel, ypixel;

  /* Process buffered packets from the client. */
  while ((type = packet_read_poll()) != SSH_MSG_NONE)
    {
      switch (type)
	{
	case SSH_CMSG_STDIN_DATA:
	  /* Stdin data from the client.  Append it to the buffer. */
	  if (fdin == -1)
	    {
	      packet_get_all();
	      break; /* Ignore any data if the client has closed stdin. */
	    }
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
#ifndef SSHD_NO_PORT_FORWARDING
	  if (no_port_forwarding_flag)
#endif /* SSHD_NO_PORT_FORWARDING */
	    {
	      int remote_channel;
	      
	      /* Get remote channel number. */
	      remote_channel = packet_get_int();
	      
	      packet_get_all();
	      
	      debug("Denied port open request.");
	      packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
	      packet_put_int(remote_channel);
	      packet_send();
	    }
#ifndef SSHD_NO_PORT_FORWARDING
	  else
	    {
	      debug("Received port open request.");
	      channel_input_port_open();
	    }
#endif /* SSHD_NO_PORT_FORWARDING */
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
	  
#ifdef SUPPORT_OLD_CHANNELS
	case SSH_MSG_CHANNEL_CLOSE:
	  debug("Received channel close.");
	  channel_input_close();
	  break;

	case SSH_MSG_CHANNEL_CLOSE_CONFIRMATION:
	  debug("Received channel close confirmation.");
	  channel_input_close_confirmation();
	  break;
#else
	case SSH_MSG_CHANNEL_INPUT_EOF:
	  debug("Received channel input eof.");
	  channel_ieof();	  
	  break;

	case SSH_MSG_CHANNEL_OUTPUT_CLOSED:
	  debug("Received channel output closed.");
	  channel_oclosed();
	  break;

#endif

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
}

/* Make packets from buffered stderr data, and buffer it for sending
   to the client. */

void make_packets_from_stderr_data()
{
  int len;

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
	  if (len > packet_max_size() / 2)
	    len = packet_max_size() / 2;
	}
      packet_start(SSH_SMSG_STDERR_DATA);
      packet_put_string(buffer_ptr(&stderr_buffer), len);
      packet_send();
      buffer_consume(&stderr_buffer, len);
      stderr_bytes += len;
    }
}

/* Make packets from buffered stdout data, and buffer it for sending to the
   client. */

void make_packets_from_stdout_data()
{
  int len;

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
	  if (len > packet_max_size() / 2)
	    len = packet_max_size() / 2;
	}
      packet_start(SSH_SMSG_STDOUT_DATA);
      packet_put_string(buffer_ptr(&stdout_buffer), len);
      packet_send();
      buffer_consume(&stdout_buffer, len);
      stdout_bytes += len;
    }
}

/* Sleep in select() until we can do something.  This will initialize the
   select masks.  Upon return, the masks will indicate which descriptors
   have data or can accept data.  Optionally, a maximum time can be specified
   for the duration of the wait (0 = infinite). */

void wait_until_can_do_something(fd_set *readset, fd_set *writeset,
				 unsigned int max_time_milliseconds,
				 void *cleanup_context)
{
  struct timeval tv, *tvp;
  int ret;

  /* Mark that we have slept since the child died. */
  child_just_terminated = 0;

  /* Initialize select() masks. */
  FD_ZERO(readset);
  
  /* Read packets from the client unless we have too much buffered stdin
     or channel data. */
  if (buffer_len(&stdin_buffer) < 4096 &&
      channel_not_very_much_buffered_data())
    FD_SET(connection_in, readset);
  
  /* If there is not too much data already buffered going to the client,
     try to get some more data from the program. */
  if (packet_not_very_much_data_to_write())
    {
      if (!fdout_eof)
	FD_SET(fdout, readset);
      if (!fderr_eof)
	FD_SET(fderr, readset);
    }
  
  FD_ZERO(writeset);
  
  /* Set masks for channel descriptors. */
  channel_prepare_select(readset, writeset);
  
  /* If we have buffered packet data going to the client, mark that
     descriptor. */
  if (packet_have_data_to_write())
    FD_SET(connection_out, writeset);
  
  /* If we have buffered data, try to write some of that data to the
     program. */
  if (fdin != -1 && buffer_len(&stdin_buffer) > 0)
    FD_SET(fdin, writeset);
  
  /* Update the maximum descriptor number if appropriate. */
  if (channel_max_fd() > max_fd)
    max_fd = channel_max_fd();
  
  /* If child has terminated, read as much as is available and then exit. */
  if (child_terminated)
    if (max_time_milliseconds == 0)
      max_time_milliseconds = 100;

  if (idle_timeout != 0 &&
      (max_time_milliseconds == 0 ||
       max_time_milliseconds / 1000 > idle_timeout))
    {
      time_t diff;

      diff = time(NULL) - idle_time_last;
      
      if (idle_timeout > diff)
	tv.tv_sec = idle_timeout - diff;
      else
	tv.tv_sec = 1;
      tv.tv_usec = 0;
      tvp = &tv;
    }
  else
    {
      if (max_time_milliseconds == 0)
	tvp = NULL;
      else
	{
	  tv.tv_sec = max_time_milliseconds / 1000;
	  tv.tv_usec = 1000 * (max_time_milliseconds % 1000);
	  tvp = &tv;
	}
    }

  /* Wait for something to happen, or the timeout to expire. */
  ret = select(max_fd + 1, readset, writeset, NULL, tvp);
  
  if (ret < 0)
    {
      if (errno != EINTR)
	error("select: %.100s", strerror(errno));
      /* At least HPSUX fails to zero these, contrary to its documentation. */
      FD_ZERO(readset);
      FD_ZERO(writeset);
    }
  
  /* If the child has terminated and there was no data, shutdown all
     descriptors to it. */
  if (ret <= 0 && child_terminated && !child_just_terminated)
    {
      /* Released the pseudo-tty. */
      if (cleanup_context)
	pty_cleanup_proc(cleanup_context);
      
      if (fdout != -1)
	close(fdout);
      fdout = -1;
      fdout_eof = 1;
      if (fderr != -1)
	close(fderr);
      fderr = -1;
      fderr_eof = 1;
      if (fdin != -1)
	close(fdin);
      fdin = -1;
    }
  else
    {
      if (ret == 0)		/* Nothing read, timeout expired */
	{
	  /* Check if idle_timeout expired ? */
	  if (idle_timeout != 0 && !child_terminated &&
	      time(NULL) - idle_time_last > idle_timeout)
	    {
	      /* Yes, kill the child */
	      kill(child_pid, SIGHUP);
	      sleep(5);
	      if (!child_terminated) /* Not exited, be rude */
		kill(child_pid, SIGKILL);
	    }
	}
      else
	{
	  /* Got something, reset idle timer */
	  idle_time_last = time(NULL);
	}
    }
}

/* Processes input from the client and the program.  Input data is stored
   in buffers and processed later. */

void process_input(fd_set *readset)
{
  int len;
  char buf[16384];

  /* Read and buffer any input data from the client. */
  if (FD_ISSET(connection_in, readset))
    {
      len = read(connection_in, buf, sizeof(buf));
      if (len == 0)
	fatal_severity(SYSLOG_SEVERITY_INFO, 
		       "Connection closed by remote host.");

      /* There is a kernel bug on Solaris that causes select to sometimes
	 wake up even though there is no data available. */
      if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
	len = 0;

      if (len < 0)
	fatal_severity(SYSLOG_SEVERITY_INFO,
		       "Read error from remote host: %.100s", strerror(errno));

      /* Buffer any received data. */
      packet_process_incoming(buf, len);
    }
  
  /* Read and buffer any available stdout data from the program. */
  if (!fdout_eof && FD_ISSET(fdout, readset))
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
  if (!fderr_eof && FD_ISSET(fderr, readset))
    {
      len = read(fderr, buf, sizeof(buf));
      if (len <= 0)
	fderr_eof = 1;
      else
	buffer_append(&stderr_buffer, buf, len);
    }
}

/* Sends data from internal buffers to client program stdin. */

void process_output(fd_set *writeset)
{
  int len;

  /* Write buffered data to program stdin. */
  if (fdin != -1 && FD_ISSET(fdin, writeset))
    {
      len = write(fdin, buffer_ptr(&stdin_buffer),
		  buffer_len(&stdin_buffer));
      if (len <= 0)
	{
	  if (errno != EWOULDBLOCK && errno != EAGAIN)
	    {
	      debug("Process_output: write to fdin failed, len = %d : %.50s",
		    len, strerror(errno));
	      if (fdin == fdout)
		shutdown(fdin, 1); /* We will no longer send. */
	      else
		close(fdin);
	      fdin = -1;
	    }
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
  if (FD_ISSET(connection_out, writeset))
    packet_write_poll();
}

/* Wait until all buffered output has been sent to the client.
   This is used when the program terminates. */

void drain_output()
{
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
}

/* Performs the interactive session.  This handles data transmission between
   the client and the program.  Note that the notion of stdin, stdout, and
   stderr in this function is sort of reversed: this function writes to
   stdin (of the child program), and reads from stdout and stderr (of the
   child program).
   This will close fdin, fdout and fderr after releasing pty (if ttyname is non
   NULL) */

void server_loop(int pid, int fdin_arg, int fdout_arg, int fderr_arg,
		 void *cleanup_context)
{
  int wait_status, wait_pid;	/* Status and pid returned by wait(). */
  int waiting_termination = 0;  /* Have displayed waiting close message. */
  unsigned int max_time_milliseconds;
  unsigned int previous_stdout_buffer_bytes;
  unsigned int stdout_buffer_bytes;
  int type;

  debug("Entering interactive session.");

  /* Initialize the SIGCHLD kludge. */
  child_pid = pid;
  child_terminated = 0;
  signal(SIGCHLD, sigchld_handler);

  /* Initialize our global variables. */
  idle_time_last = time(NULL);
  fdin = fdin_arg;
  fdout = fdout_arg;
  fderr = fderr_arg;
  connection_in = packet_get_connection_in();
  connection_out = packet_get_connection_out();
  
  previous_stdout_buffer_bytes = 0;

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
  if (connection_in > max_fd)
    max_fd = connection_in;
  if (connection_out > max_fd)
    max_fd = connection_out;

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

  /*
   * Set ttyfd to non-blocking i/o to avoid deadlock in process_output()
   * when doing large paste from xterm into slow program such as vi.  - corey
   */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(fdin, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(fdin, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

  /* Main loop of the server for the interactive session mode. */
  for (;;)
    {
      fd_set readset, writeset;

      /* Process buffered packets from the client. */
      process_buffered_input_packets();

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

      /* Make packets from buffered stderr data to send to the client. */
      make_packets_from_stderr_data();

      /* Make packets from buffered stdout data to send to the client.
	 If there is very little to send, this arranges to not send them
	 now, but to wait a short while to see if we are getting more data.
	 This is necessary, as some systems wake up readers from a pty after
	 each separate character. */
      max_time_milliseconds = 0;
      stdout_buffer_bytes = buffer_len(&stdout_buffer);
      if (stdout_buffer_bytes != 0 && stdout_buffer_bytes < 512 &&
	  stdout_buffer_bytes != previous_stdout_buffer_bytes)
	max_time_milliseconds = 17; /* try again after a while (1/60sec)*/
      else
	make_packets_from_stdout_data(); /* Send it now. */
      previous_stdout_buffer_bytes = buffer_len(&stdout_buffer);

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
	  if (!waiting_termination && !child_just_terminated)
	    {
	      const char *s = 
		"Waiting for forwarded connections to terminate...\r\n";
	      char *cp;
	      waiting_termination = 1;
	      buffer_append(&stderr_buffer, s, strlen(s));

	      /* Display list of open channels. */
	      cp = channel_open_message();
	      buffer_append(&stderr_buffer, cp, strlen(cp));
	      xfree(cp);
	    }
	}

      /* Sleep in select() until we can do something. */
      wait_until_can_do_something(&readset, &writeset,
				  max_time_milliseconds, cleanup_context);

      /* Process any channel events. */
      channel_after_select(&readset, &writeset);

      /* Process input from the client and from program stdout/stderr. */
      process_input(&readset);

      /* Process output to the client and to program stdin. */
      process_output(&writeset);
    }

 quit:
  /* Cleanup and termination code. */

  /* Wait until all output has been sent to the client. */
  drain_output();

  debug("End of interactive session; stdin %ld, stdout (read %ld, sent %ld), stderr %ld bytes.",
	stdin_bytes, fdout_bytes, stdout_bytes, stderr_bytes);

  /* Free and clear the buffers. */
  buffer_free(&stdin_buffer);
  buffer_free(&stdout_buffer);
  buffer_free(&stderr_buffer);

  /* Released the pseudo-tty. */
  if (cleanup_context)
    pty_cleanup_proc(cleanup_context);
  
  /* Close the file descriptors. */
  if (fdout != -1)
    close(fdout);
  if (fdin != -1 && fdin != fdout)
    close(fdin);
  if (fderr != -1)
    close(fderr);
  
  /* Stop listening for channels; this removes unix domain sockets. */
  channel_stop_listening();
  
  /* We no longer want our SIGCHLD handler to be called. */
  signal(SIGCHLD, SIG_DFL);

  if (child_terminated)
    wait_status = child_wait_status;
  else
    {
      /* Wait for the child to exit.  Get its exit status. */
      wait_pid = wait(&wait_status);
      if (wait_pid < 0)
	{
	  packet_disconnect("wait: %.100s", strerror(errno));
	}
      else
	{
	  /* Check if it matches the process we forked. */
	  if (wait_pid != pid)
	    error("Strange, wait returned pid %d, expected %d", wait_pid, pid);
	}
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
	  if (type != SSH_CMSG_EXIT_CONFIRMATION)
	    {
	      packet_get_all();
	      debug("Received packet of type %d after exit.\n", type);
	    }
	}
      while (type != SSH_CMSG_EXIT_CONFIRMATION);

      debug("Received exit confirmation.");
      return;
    }

  /* Check if the program terminated due to a signal. */
  if (WIFSIGNALED(wait_status))
    packet_disconnect("Command terminated on signal %d.", 
		      WTERMSIG(wait_status));

  /* Some weird exit cause.  Just exit. */
  packet_disconnect("wait returned status %04x.", wait_status);
  /*NOTREACHED*/
}

