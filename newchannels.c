/*

channels.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 24 16:35:24 1995 ylo

This file contains functions for generic socket connection forwarding.
There is also code for initiating connection forwarding for X11 connections,
arbitrary tcp/ip connections, and the authentication agent connection.

*/

/*
 * $Id: newchannels.c,v 1.37 1997/04/17 04:01:22 kivinen Exp $
 * $Log: newchannels.c,v $
 * Revision 1.37  1997/04/17 04:01:22  kivinen
 * 	Removed extra port variable. Added return -1 to
 * 	channel_allocate to get rid of warning.
 *
 * Revision 1.36  1997/04/05 21:48:54  kivinen
 * 	Fixed some debug messages (removed extra newline at the end).
 * 	Added clearing of input buffer after output have closed.
 *
 * Revision 1.35  1997/03/26 07:14:47  kivinen
 * 	Added checks about failed read and write for open channel.
 *
 * Revision 1.34  1997/03/25 05:39:36  kivinen
 * 	Added check that hp == NULL in hpux kludge display setting.
 *
 * Revision 1.33  1997/03/19 19:25:01  kivinen
 * 	Added input buffer clearing for error conditions, so packet.c
 * 	can check that buffer must be empty before new packet is read
 * 	in.
 *
 * Revision 1.32  1997/03/19 17:58:10  kivinen
 * 	Added checks that x11 and authentication agent forwarding is
 * 	really requested when open requests is received.
 * 	Added checks that strlen(hostname) <= 255.
 *
 * Revision 1.31  1997/01/23 14:41:35  ttsalo
 *     Fixed a typo (%.200d -> %.200s)
 *
 * Revision 1.30  1997/01/22 21:18:58  ttsalo
 *     Fixed a memory deallocation bug
 *
 * Revision 1.29  1996/12/04 19:04:40  ttsalo
 *     Changed a debug message
 *
 * Revision 1.28  1996/12/04 18:16:52  ttsalo
 *     Added printing of channel type in allocation
 *
 * Revision 1.27  1996/11/27 15:38:24  ttsalo
 *     Added X11DisplayOffset-option
 *
 * Revision 1.26  1996/11/24 08:22:39  kivinen
 * 	Added tcp wrapper code to x11 and port forwarding.
 * 	Removed extra channel_send_ieof from rejected
 * 	X11 channel open.
 * 	Fixed channel_request_remote_forwarding so it wont call fatal
 * 	if the other ends doens't permit forwarding.
 * 	Changed auth_input_request_forwarding to return true if it
 * 	succeeds and false otherwise. Changed it to send errors with
 * 	packet_send_debug to client instead of disconnect. Made the
 * 	error messages more verbose.
 *
 * Revision 1.25  1996/11/09 17:00:32  ttsalo
 *       Chdir out from socket directory before deleting it
 *
 * Revision 1.24  1996/11/04 06:34:45  ylo
 * 	Fixed a number of erroneous messages.
 *
 * Revision 1.23  1996/10/30 14:24:53  ttsalo
 *       Changed two stats to lstats
 *
 * Revision 1.22  1996/10/29 22:42:43  kivinen
 * 	log -> log_msg. Fixed auth_input_request_forwarding to check
 * 	that the parent directory of SSH_AGENT_SOCKET_DIR and the ..
 * 	are same (check that the last component of agent directory
 * 	isn't symlink).
 * 	Disconnect if agent directory mkdir fails.
 * 	Renamed remotech to remote_channel in
 * 	auth_input_open_request.
 *
 * Revision 1.21  1996/10/29 14:18:51  ttsalo
 *       Fixed a bug
 *
 * Revision 1.20  1996/10/29 14:07:24  ttsalo
 *       Clarified some error messages
 *
 * Revision 1.19  1996/10/29 13:38:45  ttsalo
 * 	Improved the security of auth_input_request_forwarding()
 *
 * Revision 1.18  1996/10/24 14:05:10  ttsalo
 *       Cleaning up old fd-auth trash
 *
 * Revision 1.17  1996/10/20 16:27:34  ttsalo
 * 	Many changes, agent stuff should now work as defined in the specs
 *
 * Revision 1.16  1996/09/28 16:26:09  ylo
 * 	Added a workaround for channel deadlocks...  This may cause
 * 	sshd to grow occasionally, and indefinitely in some situations.
 *
 * Revision 1.15  1996/09/27 17:21:39  ylo
 * 	Merged ultrix, Next and Linux patches from Corey Satten. This
 * 	effectively puts all file descriptors in non-blocking mode,
 * 	because these systems appear to sometimes wake up from select
 * 	and then block in write even when they are not supposed to.
 *
 * Revision 1.14  1996/09/27 14:00:11  ttsalo
 * 	Replaced a chmod with umask setting, chmod was dangerous.
 *
 * Revision 1.13  1996/09/14 08:44:12  ylo
 * 	Print X11 auth protocols if different.
 *
 * Revision 1.12  1996/09/14 08:42:14  ylo
 * 	Fixed a (minor) bug in interactive output packet sizing.
 * 	Reduced maximum non-interactive packet size to 8192.
 *
 * Revision 1.11  1996/09/12 18:31:11  ttsalo
 * 	st->uid to st->st.uid
 *
 * Revision 1.10  1996/09/11 17:56:22  kivinen
 * 	Fixed serious security bug in auth_input_request_forwarding,
 * 	now we chown the directory only if we created it. Changed
 * 	auth_input_request_forwarding to check the permissions of
 * 	directory itself and not to call
 * 	userfile_check_owner_permissions (it doesn't check for read
 * 	and execute permissions).
 *
 * Revision 1.9  1996/09/08 17:21:06  ttsalo
 * 	A lot of changes in agent-socket handling
 *
 * Revision 1.8  1996/09/04 12:41:49  ttsalo
 * 	Minor fixes
 *
 * Revision 1.7  1996/08/29 14:51:25  ttsalo
 * 	Agent-socket directory handling implemented
 *
 * Revision 1.6  1996/08/21 20:43:54  ttsalo
 * 	Made ssh-agent use a different, more secure way of storing
 * 	it's initial socket.
 *
 * Revision 1.5  1996/07/31 07:10:35  huima
 * 	Fixed the connection closing bug.
 *
 * Revision 1.4  1996/07/15 00:28:57  ylo
 * 	When an X11 connection is rejected, log where the rejected
 * 	connection came from.
 *
 * Revision 1.3  1996/07/12 07:22:47  ttsalo
 * 	Patch from <Rein.Tollevik@si.sintef.no> to handle HP-UX
 * 	nonstandard X11 socket kludging.
 *
 * Revision 1.2  1996/05/06 09:53:24  huima
 * Fixed a major in the channels allocation.
 *
 * Revision 1.1  1996/04/22  23:43:52  huima
 * New channels code added to the repository.
 *
 * Revision 1.1.1.1  1996/02/18  21:38:12  ylo
 * 	Imported ssh-1.2.13
 *
 * Revision 1.13  1995/10/02  01:20:08  ylo
 * 	Added a cast to avoid compiler warning.
 *
 * Revision 1.12  1995/09/24  23:58:49  ylo
 * 	Added support for screen number in X11 forwarding.
 * 	Reduced max packet size in interactive mode from 1024 bytes to
 * 	512 bytes for forwarded connections.
 *
 * Revision 1.11  1995/09/21  17:08:40  ylo
 * 	Support AF_UNIX_SIZE.
 *
 * Revision 1.10  1995/09/10  23:25:35  ylo
 * 	Fixed HPSUX DISPLAY kludge.
 *
 * Revision 1.9  1995/09/10  22:45:23  ylo
 * 	Changed Unix domain socket and umask stuff.
 *
 * Revision 1.8  1995/09/09  21:26:39  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.7  1995/09/06  15:58:14  ylo
 * 	Added BROKEN_INET_ADDR.
 *
 * Revision 1.6  1995/08/29  22:20:40  ylo
 * 	New file descriptor code for agent forwarding.
 *
 * Revision 1.5  1995/08/21  23:22:49  ylo
 * 	Clear sockaddr_in structures before use.
 *
 * 	Reject X11 connections that don't match fake data.
 *
 * Revision 1.4  1995/08/18  22:47:11  ylo
 * 	Fixed a typo (missing parentheses in packet_is_interactive
 * 	call).
 *
 * 	Removed extra shutdown in channel_close_all().  This caused
 * 	the "accept: software caused connection abort" messages and
 * 	busy looping that made the previous version of ssh unusable on
 * 	most systems.
 *
 * Revision 1.3  1995/07/27  02:16:43  ylo
 * 	Fixed output draining on forwarded TCP/IP connections.
 * 	Use smaller packets for interactive sessions.
 *
 * Revision 1.2  1995/07/13  01:19:29  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#if !defined(HAVE_GETHOSTNAME) || defined(HPSUX_NONSTANDARD_X11_KLUDGE)
#include <sys/utsname.h>
#endif
#include "ssh.h"
#include "packet.h"
#include "xmalloc.h"
#include "buffer.h"
#include "authfd.h"
#include "emulate.h"
#include "servconf.h"
#ifdef LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
#endif /* LIBWRAP */

/* Directory in which the fake unix-domain X11 displays reside. */
#define X11_DIR "/tmp/.X11-unix"

/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Definitions for channel types. */
#define SSH_CHANNEL_FREE		0 /* This channel is free (unused). */
#define SSH_CHANNEL_X11_LISTENER	1 /* Listening for inet X11 conn. */
#define SSH_CHANNEL_PORT_LISTENER	2 /* Listening on a port. */
#define SSH_CHANNEL_OPENING		3 /* waiting for confirmation */
#define SSH_CHANNEL_OPEN		4 /* normal open two-way channel */
/* obsolete SSH_CHANNEL_CLOSED		5    waiting for close confirmation */
/* obsolete SSH_CHANNEL_AUTH_FD		6    authentication fd */
/* obsolete SSH_CHANNEL_AUTH_SOCKET	7    authentication socket */
/* obsolete SSH_CHANNEL_AUTH_SOCKET_FD	8    connection to auth socket */
#define SSH_CHANNEL_X11_OPEN		9 /* reading first X11 packet */
#define SSH_CHANNEL_AUTH_LISTENER      10 /* Agent proxy listening for
					     connections */

/* Status flags */

#define STATUS_INPUT_SOCKET_CLOSED	0x0001
#define STATUS_OUTPUT_SOCKET_CLOSED	0x0002
#define STATUS_EOF_SENT			0x0004
#define STATUS_EOF_RECEIVED		0x0008
#define STATUS_CLOSE_SENT		0x0010
#define STATUS_CLOSE_RECEIVED		0x0020
#define STATUS_KLUDGE_A			0x0040
#define STATUS_KLUDGE_B       		0x0080

#define STATUS_TERMINATE		0x003f

/* Data structure for channel data.  This is iniailized in channel_allocate
   and cleared in channel_free. */

typedef struct
{
  int type;
  int sock;

  int remote_id, local_id;
  int status_flags; /* for keeping book on the internal state */

  Buffer input;
  Buffer output;

  char path[200]; /* path for unix domain sockets, or host name for forwards */
  int host_port;  /* port to connect for forwards */
  int listening_port; /* port being listened for forwards */
  char *remote_name;

  int is_x_connection;
} Channel;

/* Pointer to an array containing all allocated channels.  The array is
   dynamically extended as needed. */
static Channel *channels = NULL;

/* Size of the channel array.  All slots of the array must always be
   initialized (at least the type field); unused slots are marked with
   type SSH_CHANNEL_FREE. */
static int channels_alloc = 0;

/* Number of currently used channels.  Used to determine if we should
   expand the array. */
static int channels_used = 0;

/* Maximum file descriptor value used in any of the channels.  This is updated
   in channel_allocate. */
static int channel_max_fd_value = 0;

/* These two variables are for authentication agent forwarding. */
static int channel_forwarded_auth_fd = -1;
static char *channel_forwarded_auth_socket_name = NULL;

/* Agent forwarding socket directory name */
static char *channel_forwarded_auth_socket_dir_name = NULL;

/* Saved X11 authentication protocol name. */
char *x11_saved_proto = NULL;

/* Saved X11 authentication data.  This is the real data. */
char *x11_saved_data = NULL;
unsigned int x11_saved_data_len = 0;

/* Fake X11 authentication data.  This is what the server will be sending
   us; we should replace any occurrences of this by the real data. */
char *x11_fake_data = NULL;
unsigned int x11_fake_data_len;

/* Data structure for storing which hosts are permitted for forward requests.
   The local sides of any remote forwards are stored in this array to prevent
   a corrupt remote server from accessing arbitrary TCP/IP ports on our
   local network (which might be behind a firewall). */
typedef struct
{
  char *host;		/* Host name. */
  int port;		/* Port number. */
} ForwardPermission;

/* List of all permitted host/port pairs to connect. */
static ForwardPermission permitted_opens[SSH_MAX_FORWARDS_PER_DIRECTION];
/* Number of permitted host/port pairs in the array. */
static int num_permitted_opens = 0;
/* If this is true, all opens are permitted.  This is the case on the
   server on which we have to trust the client anyway, and the user could
   do anything after logging in anyway. */
static int all_opens_permitted = 0;

/* X11 forwarding permitted */
static int x11_forwarding_permitted = 0;

/* Agent forwarding permitted */
static int auth_forwarding_permitted = 0;

/* This is set to true if both sides support SSH_PROTOFLAG_HOST_IN_FWD_OPEN. */
static int have_hostname_in_open = 0;

/* Sets specific protocol options. */

void channel_set_options(int hostname_in_open)
{
  have_hostname_in_open = hostname_in_open;
}

/* Permits opening to any host/port in SSH_MSG_PORT_OPEN.  This is usually
   called by the server, because the user could connect to any port anyway,
   and the server has no way to know but to trust the client anyway. */

void channel_permit_all_opens()
{
  all_opens_permitted = 1;
}

/* Allocate a new channel object and set its type and socket. 
   This will cause remote_name to be freed. */

int channel_allocate(int type, int sock, char *remote_name)
{
  int i;

  /* Update the maximum file descriptor value. */
  if (sock > channel_max_fd_value)
    channel_max_fd_value = sock;

  /* Do initial allocation if this is the first call. */
  if (channels_alloc == 0)
    {
      channels_alloc = 10;
      channels = xmalloc(channels_alloc * sizeof(Channel));
      for (i = 0; i < channels_alloc; i++)
	channels[i].type = SSH_CHANNEL_FREE;

      /* Kludge: arrange a call to channel_stop_listening if we terminate
	 with fatal(). */
      fatal_add_cleanup((void (*)(void *))channel_stop_listening, NULL);
    }

  i = 0;

  if (channels_used == channels_alloc)
    {
      /* There are no free slots.  Must expand the array. */
      channels_alloc += 10;
      debug("Expanding the array...");
      channels = xrealloc(channels, channels_alloc * sizeof(Channel));
      for (i = channels_used; i < channels_alloc; i++)
	channels[i].type = SSH_CHANNEL_FREE;
      i = channels_used;
      debug("Array now %d channels [first free at %d].",
	    channels_alloc, i);
    }

  /* Try to find a free slot where to put the new channel. */
  while (i < channels_alloc)
    {
      if (channels[i].type == SSH_CHANNEL_FREE)
	{
	  /* Found a free slot. 
	     Initialize the fields and return its number. */
	  buffer_init(&channels[i].input);
	  buffer_init(&channels[i].output);
	  channels[i].type = type;
	  channels[i].sock = sock;
	  channels[i].remote_id = -1;
	  channels[i].remote_name = remote_name;
	  channels[i].status_flags = 0;
	  channels[i].local_id = i;
	  channels[i].is_x_connection = 0;
	  channels_used++;
	  debug("Allocated channel %d of type %d.", i, type);
	  return i;
	}
      i++;
    }
  fatal ("Internal bug in channel_allocate.");
  return -1;
}

/* Free the channel and close its socket. */

void channel_free(int channel)
{
  assert(channel >= 0 && channel < channels_alloc &&
	 channels[channel].type != SSH_CHANNEL_FREE);
  close(channels[channel].sock);
  buffer_free(&channels[channel].input);
  buffer_free(&channels[channel].output);
  channels[channel].type = SSH_CHANNEL_FREE;
  channels_used--;
  if (channels[channel].remote_name)
    {
      xfree(channels[channel].remote_name);
      channels[channel].remote_name = NULL;
    }
}

/* Support for the new protocol */

/* A channel can be freed when it has sent and received
   input eof and output closed */

void channel_check_termination(Channel *ch)
{
  if ((ch->status_flags & STATUS_TERMINATE) == STATUS_TERMINATE)
    {
#ifdef SUPPORT_OLD_CHANNELS
      if ((emulation_information & EMULATE_OLD_CHANNEL_CODE)
	  && !(ch->status_flags & STATUS_KLUDGE_A))
	{
	  ch->status_flags &= ~(STATUS_CLOSE_RECEIVED | STATUS_EOF_RECEIVED);
	  debug("Discarding termination of channel %d.", ch->local_id);
	  return;
	}
#endif
      debug("Channel %d terminates.", ch->local_id);
#ifdef SUPPORT_OLD_CHANNELS
      if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
	if (ch->status_flags & STATUS_KLUDGE_B)
	  {
	    packet_start(SSH_MSG_CHANNEL_CLOSE_CONFIRMATION);
	    packet_put_int(ch->remote_id);
	    packet_send();
	  }
#endif
      channel_free(ch->local_id);
    }
}

/* If ieof has not yet been sent, send it */

void channel_send_ieof(Channel *ch)
{
  if (!(ch->status_flags & STATUS_EOF_SENT))
    {
      debug("Channel %d sends ieof.", ch->local_id);
      ch->status_flags |= STATUS_EOF_SENT;

#ifdef SUPPORT_OLD_CHANNELS
      /* This is SSH_MSG_CHANNEL_CLOSE in the old protocol */
#endif

      packet_start(SSH_MSG_CHANNEL_INPUT_EOF);
      packet_put_int(ch->remote_id);
      packet_send();

#ifdef SUPPORT_OLD_CHANNELS
      if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
	ch->status_flags |= STATUS_CLOSE_SENT;
#endif

      channel_check_termination(ch);
    }
}

/* If oclosed has not yet been sent, send it */
#ifdef SUPPORT_OLD_CHANNELS
/* This will be never called if we're emulating the old code */
#endif

void channel_send_oclosed(Channel *ch)
{
  
  if (!(ch->status_flags & STATUS_CLOSE_SENT))
    {
      debug("Channel %d sends oclosed.", ch->local_id);
      ch->status_flags |= STATUS_CLOSE_SENT;

      packet_start(SSH_MSG_CHANNEL_OUTPUT_CLOSED);
      packet_put_int(ch->remote_id);
      packet_send();

      channel_check_termination(ch);
    }
}

/* Close input if hasn't been done yet. Input buffer is not discarded,
   because we want to drain it over the channel. */

#ifdef SUPPORT_OLD_CHANNELS
void channel_close_output(Channel *ch);
#endif

void channel_close_input(Channel *ch)
{
  if (!(ch->status_flags & STATUS_INPUT_SOCKET_CLOSED))
    {
      debug("Channel %d closes incoming data stream.", ch->local_id);
      ch->status_flags |= STATUS_INPUT_SOCKET_CLOSED;
      shutdown(ch->sock, 0);
      if (ch->type != SSH_CHANNEL_OPEN)
	{
	  channel_send_ieof(ch);
	}
#ifdef SUPPORT_OLD_CHANNELS
      if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
	{
	  channel_close_output(ch);
	}
#endif
    }
}

/* Close output if it hasn't been done yet. Output buffer is
   discarded, because we couldn't put it anywhere else (as the socket
   is closed). Send info about the close immediately. */

void channel_close_output(Channel *ch)
{
  if (!(ch->status_flags & STATUS_OUTPUT_SOCKET_CLOSED))
    {
      debug("Channel %d closes outgoing data stream.", ch->local_id);
      ch->status_flags |= STATUS_OUTPUT_SOCKET_CLOSED;
      shutdown(ch->sock, 1);
      if (buffer_len(&ch->output))
	buffer_consume(&ch->output, buffer_len(&ch->output));
#ifdef SUPPORT_OLD_CHANNELS
      if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
	{
	  debug("This is emulation.");
	  channel_close_input(ch);
	}
      else
#endif
	channel_send_oclosed(ch);      
    }
}

/* Receive input eof. Nothing is done yet, because the output buffer
   might want to drain away. */

void channel_receive_ieof(Channel *ch)
{
  if (ch->status_flags & STATUS_EOF_RECEIVED)
    packet_disconnect("Received double input eof.");

  debug("Channel %d receives input eof.", ch->local_id);
  ch->status_flags |= STATUS_EOF_RECEIVED;
  if (ch->is_x_connection)
    {
      debug("X problem fix: close the other direction.");
      channel_close_input(ch);
    }
  if (ch->type != SSH_CHANNEL_OPEN)
    channel_close_output(ch);
  channel_check_termination(ch);
}

/* Receive output closed. Input will be immediately closed,
   because the other party is not interested in our packets. */

void channel_receive_oclosed(Channel *ch)
{
  if (ch->status_flags & STATUS_CLOSE_RECEIVED)
    packet_disconnect("Received double close.");

  debug("Channel %d receives output closed.", ch->local_id);
  ch->status_flags |= STATUS_CLOSE_RECEIVED;
  buffer_clear(&ch->input);
  channel_close_input(ch);
  channel_check_termination(ch);
}

/* This is called after receiving CHANNEL_INPUT_EOF */

void channel_ieof()
{
  int channel;
  /* Get the channel number and verify it. */
  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type == SSH_CHANNEL_FREE)
    packet_disconnect("Received ieof for nonexistent channel %d.", channel);

  channel_receive_ieof(&channels[channel]);
}

/* This is called after receiving CHANNEL_OUTPUT_CLOSED */
void channel_oclosed()
{
  int channel;
  /* Get the channel number and verify it. */
  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type == SSH_CHANNEL_FREE)
    packet_disconnect("Received oclosed for nonexistent channel %d.", channel);

  channel_receive_oclosed(&channels[channel]);
}

#ifdef SUPPORT_OLD_CHANNELS
void channel_emulated_close(int set_a)
{
  int channel;
  
  debug("Emulated close.");

  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type == SSH_CHANNEL_FREE)
    packet_disconnect("Received emulated_close for nonexistent channel %d.",
		      channel);

  if (set_a)
    channels[channel].status_flags |= STATUS_KLUDGE_A;
  else
    channels[channel].status_flags |= STATUS_KLUDGE_B;

  channel_receive_ieof(&channels[channel]);  
  channel_receive_oclosed(&channels[channel]);
}
#endif

/* This is called just before select() to add any bits relevant to
   channels in the select bitmasks. */

void channel_prepare_select(fd_set *readset, fd_set *writeset)
{
  int i;
  Channel *ch;
  unsigned char *ucp;
  unsigned int proto_len, data_len;

  for (i = 0; i < channels_alloc; i++)
    {
      ch = &channels[i];
    redo:
      switch (ch->type)
	{
	case SSH_CHANNEL_X11_LISTENER:
	case SSH_CHANNEL_PORT_LISTENER:
	case SSH_CHANNEL_AUTH_LISTENER:
	  FD_SET(ch->sock, readset);
	  break;
	  
	case SSH_CHANNEL_OPEN:

	  if ((buffer_len(&ch->input) < packet_max_size() / 2)
	      && (!(ch->status_flags & STATUS_INPUT_SOCKET_CLOSED)))
	    FD_SET(ch->sock, readset);

          if (!(ch->status_flags & STATUS_OUTPUT_SOCKET_CLOSED))
            {
              if (buffer_len(&ch->output) > 0)
		{
		  FD_SET(ch->sock, writeset);
		}
	      else
		{
		  if (ch->status_flags & STATUS_EOF_RECEIVED)
		    {
		      channel_close_output(ch);
		    }
		}
            }

	  break;
	  
	case SSH_CHANNEL_X11_OPEN:
	  /* This is a special state for X11 authentication spoofing.  An
	     opened X11 connection (when authentication spoofing is being
	     done) remains in this state until the first packet has been
	     completely read.  The authentication data in that packet is
	     then substituted by the real data if it matches the fake data,
	     and the channel is put into normal mode. */

	  /* Check if the fixed size part of the packet is in buffer. */
	  if (buffer_len(&ch->output) < 12)
	    break;

	  /* Parse the lengths of variable-length fields. */
	  ucp = (unsigned char *)buffer_ptr(&ch->output);
	  if (ucp[0] == 0x42)
	    { /* Byte order MSB first. */
	      proto_len = 256 * ucp[6] + ucp[7];
	      data_len = 256 * ucp[8] + ucp[9];
	    }
	  else
	    if (ucp[0] == 0x6c)
	      { /* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	      }
	    else
	      {
		debug("Initial X11 packet contains bad byte order byte: 0x%x",
		      ucp[0]);
		ch->type = SSH_CHANNEL_OPEN;
		goto reject;
	      }

	  /* Check if the whole packet is in buffer. */
	  if (buffer_len(&ch->output) <
	      12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
	    break;
	  
	  /* Check if authentication protocol matches. */
	  if (proto_len != strlen(x11_saved_proto) || 
	      memcmp(ucp + 12, x11_saved_proto, proto_len) != 0)
	    {
	      if (proto_len > 100)
		proto_len = 100; /* Limit length of output. */
	      debug("X11 connection uses different authentication protocol: '%.100s' vs. '%.*s'.",
		    x11_saved_proto,
		    proto_len, (const char *)(ucp + 12));
	      ch->type = SSH_CHANNEL_OPEN;
	      goto reject;
	    }

	  /* Check if authentication data matches our fake data. */
	  if (data_len != x11_fake_data_len ||
	      memcmp(ucp + 12 + ((proto_len + 3) & ~3),
		     x11_fake_data, x11_fake_data_len) != 0)
	    {
	      debug("X11 auth data does not match fake data.");
	      ch->type = SSH_CHANNEL_OPEN;
	      goto reject;
	    }

	  /* Received authentication protocol and data match our fake data.
	     Substitute the fake data with real data. */
	  assert(x11_fake_data_len == x11_saved_data_len);
	  memcpy(ucp + 12 + ((proto_len + 3) & ~3),
		 x11_saved_data, x11_saved_data_len);

	  /* Start normal processing for the channel. */
	  ch->type = SSH_CHANNEL_OPEN;
	  goto redo;
	  
	reject:
	  /* We have received an X11 connection that has bad authentication
	     information. */
	  log_msg("X11 connection rejected because of wrong authentication.\r\n");
	  if (ch->remote_name)
	    log_msg("Rejected connection: %.200s\r\n", ch->remote_name);
	  buffer_clear(&ch->input);
	  buffer_clear(&ch->output);
	  channel_close_input(ch);
	  channel_close_output(ch);
	  /* Output closed has been sent in close_output except if
	     we're emulating the old code, but then we wouldn't send
	     it anyway. */
	  /* We will then wait until both closing packets have come,
	     then the channel gets destroyed - and the socket
	     closed. */
	  break;
	  
	case SSH_CHANNEL_FREE:
	default:
	  continue;
	}
    }
}

/* After select, perform any appropriate operations for channels which
   have events pending. */

void channel_after_select(fd_set *readset, fd_set *writeset)
{
  struct sockaddr addr;
  int addrlen, newsock, i, newch, len, temp;
  Channel *ch;
  char buf[16384], *remote_hostname;
  
  /* Loop over all channels... */
  for (i = 0; i < channels_alloc; i++)
    {
      ch = &channels[i];
      switch (ch->type)
	{
	case SSH_CHANNEL_X11_LISTENER:
	  /* This is our fake X11 server socket. */
	  if (FD_ISSET(ch->sock, readset))
	    {
	      debug("X11 connection requested.");
	      addrlen = sizeof(addr);
	      newsock = accept(ch->sock, &addr, &addrlen);
	      if (newsock < 0)
		{
		  error("accept: %.100s", strerror(errno));
		  break;
		}
	      remote_hostname = get_remote_hostname(newsock);
	      sprintf(buf, "X11 connection from %.200s port %d",
		      remote_hostname, get_peer_port(newsock));
	      xfree(remote_hostname);
#ifdef LIBWRAP
	      {
		struct request_info req;
		struct servent *serv;
		
		/* fill req struct with port name and fd number */
		request_init(&req, RQ_DAEMON, "sshdfwd-X11",
			     RQ_FILE, newsock, NULL);
		fromhost(&req);
		if (!hosts_access(&req))
		  {
		    packet_send_debug("Fwd X11 connection from %.500s refused by tcp_wrappers.", eval_client(&req));
		    error("Fwd X11 connection from %.500s refused by tcp_wrappers.",
			  eval_client(&req));
		    shutdown(newsock, 2);
		    close(newsock);
		    break;
		  }
		log_msg("fwd X11 connect from %.500s", eval_client(&req));
	      }
#endif /* LIBWRAP */
	      newch = channel_allocate(SSH_CHANNEL_OPENING, newsock, 
				       xstrdup(buf));
	      channels[newch].is_x_connection = 1;
	      packet_start(SSH_SMSG_X11_OPEN);
	      packet_put_int(newch);
	      if (have_hostname_in_open)
		packet_put_string(buf, strlen(buf));
	      packet_send();
	    }
	  break;
	  
	case SSH_CHANNEL_PORT_LISTENER:
	  /* This socket is listening for connections to a forwarded TCP/IP
	     port. */
	  if (FD_ISSET(ch->sock, readset))
	    {
	      debug("Connection to port %d forwarding to %.100s:%d requested.",
		    ch->listening_port, ch->path, ch->host_port);
	      addrlen = sizeof(addr);
	      newsock = accept(ch->sock, &addr, &addrlen);
	      if (newsock < 0)
		{
		  error("accept: %.100s", strerror(errno));
		  break;
		}
	      remote_hostname = get_remote_hostname(newsock);
	      sprintf(buf, "port %d, connection from %.200s port %d",
		      ch->listening_port, remote_hostname,
		      get_peer_port(newsock));
	      xfree(remote_hostname);
#ifdef LIBWRAP
	      {
		struct request_info req;
		struct servent *serv;
		char fwdportname[32];
		
		/* try to find port's name in /etc/services */
		serv = getservbyport(htons(ch->listening_port), "tcp");
		if (serv == NULL)
		  {
		    /* not found (or faulty getservbyport) -
		       use the number as a name */
		    sprintf(fwdportname,"sshdfwd-%d", ch->listening_port);
		  }
		else
		  {
		    sprintf(fwdportname, "sshdfwd-%.20s", serv->s_name);
		  }
		/* fill req struct with port name and fd number */
		request_init(&req, RQ_DAEMON, fwdportname,
			     RQ_FILE, newsock, NULL);
		fromhost(&req);
		if (!hosts_access(&req))
		  {
		    packet_send_debug("Fwd connection from %.500s to local port %s refused by tcp_wrappers.",
				      eval_client(&req), fwdportname);
		    error("Fwd connection from %.500s to local port %s refused by tcp_wrappers.",
			  eval_client(&req), fwdportname);
		    shutdown(newsock, 2);
		    close(newsock);
		    break;
		  }
		log_msg("fwd connect from %.500s to local port %s",
		    eval_client(&req), fwdportname);
	      }
#endif /* LIBWRAP */
	      newch = channel_allocate(SSH_CHANNEL_OPENING, newsock, 
				       xstrdup(buf));
	      packet_start(SSH_MSG_PORT_OPEN);
	      packet_put_int(newch);
	      packet_put_string(ch->path, strlen(ch->path));
	      packet_put_int(ch->host_port);
	      if (have_hostname_in_open)
		packet_put_string(buf, strlen(buf));
	      packet_send();
	    }
	  break;

	case SSH_CHANNEL_AUTH_LISTENER:
	  /* This socket is listening for connections to a forwarded agent
	     port. */
	  if (FD_ISSET(ch->sock, readset))
	    {
	      debug("Connection to agent proxy requested from unix domain socket.");
	      addrlen = sizeof(addr);
	      newsock = accept(ch->sock, &addr, &addrlen);
	      if (newsock < 0)
		{
		  error("accept: %.100s", strerror(errno));
		  break;
		}
	      sprintf(buf, "Forwarded agent connection");
	      newch = channel_allocate(SSH_CHANNEL_OPENING, newsock, 
				       xstrdup(buf));
	      packet_start(SSH_SMSG_AGENT_OPEN);
	      packet_put_int(newch);
	      packet_send();
	    }
	  break;

	case SSH_CHANNEL_OPEN:
	  /* This is an open two-way communication channel.  It is not of
	     interest to us at this point what kind of data is being
	     transmitted. */
	  /* Read available incoming data and append it to buffer. */
	  if (FD_ISSET(ch->sock, readset))
	    {
	      len = sizeof(buf);
	      if (len > packet_max_size() / 4)
		len = packet_max_size() / 4;
	      len = read(ch->sock, buf, len);
	      if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		goto no_rdata;
	      if (len <= 0)
		{
		  channel_close_input(ch);
		  break;
		}
	      buffer_append(&ch->input, buf, len);
	    }
	no_rdata:
	  /* Send buffered output data to the socket. */
	  if (FD_ISSET(ch->sock, writeset) &&
	      (temp = buffer_len(&ch->output)) > 0)
	    {
	      len = write(ch->sock, buffer_ptr(&ch->output), temp);
	      if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		goto no_wdata;
	      if (len <= 0)
		{
		  channel_close_output(ch);
		  break;
		}
	      buffer_consume(&ch->output, len);
	    }
	no_wdata:
	  break;

	case SSH_CHANNEL_X11_OPEN:
	case SSH_CHANNEL_FREE:
	default:
	  continue;
	}
    }
}

/* If there is data to send to the connection, send some of it now. */

void channel_output_poll()
{
  int len, i;
  Channel *ch;

  for (i = 0; i < channels_alloc; i++)
    {
      /* If we have very much data going to the output socket, don't send more
	 now. */
      if (!packet_not_very_much_data_to_write())
	break; /* Don't send any more data now. */

      ch = &channels[i];
      /* We are only interested in channels that can have buffered incoming
	 data. */
      if (ch->type != SSH_CHANNEL_OPEN)
	continue;

      /* Get the amount of buffered data for this channel. */
      len = buffer_len(&ch->input);
      if (len > 0)
	{
	  /* Send some data for the other side over the secure connection. */
	  if (packet_is_interactive())
	    {
	      if (len > 512)
		len = 512;
	    }
	  else
	    {
	      if (len > 8192)
		len = 8192;  /* Keep the packets at reasonable size. */
	      if (len > packet_max_size() / 2)
		len = packet_max_size() / 2;
	    }
	  packet_start(SSH_MSG_CHANNEL_DATA);
	  packet_put_int(ch->remote_id);
	  packet_put_string(buffer_ptr(&ch->input), len);
	  packet_send();
	  buffer_consume(&ch->input, len);
	}
      /* check if we should send epsilon out */
      else
	{
	  /* input buffer is empty, input socket closed,
	     input eof not sent, send it now */
	  if ((ch->status_flags & (STATUS_INPUT_SOCKET_CLOSED |
				   STATUS_EOF_SENT)) ==
	      STATUS_INPUT_SOCKET_CLOSED)
	    {
	      channel_send_ieof(ch);
	    }
	}
    }
}

/* This is called when a packet of type CHANNEL_DATA has just been received.
   The message type has already been consumed, but channel number and data
   is still there. */

void channel_input_data()
{
  int channel;
  char *data;
  unsigned int data_len;

  /* Get the channel number and verify it. */
  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type == SSH_CHANNEL_FREE)
    packet_disconnect("Received data for nonexistent channel %d.", channel);
  
  /* Ignore any data for non-open channels (might happen on close) */
  if (channels[channel].type != SSH_CHANNEL_OPEN &&
      channels[channel].type != SSH_CHANNEL_X11_OPEN)
    {
      packet_get_all();
      return;
    }
  
  /* Get the data. */
  
  if (channels[channel].status_flags & STATUS_EOF_RECEIVED)
    packet_disconnect("Other party sent data after eof for channel %d.",
		      channel);
  
  if (!(channels[channel].status_flags & STATUS_OUTPUT_SOCKET_CLOSED)) {
    data = packet_get_string(&data_len);
    buffer_append(&channels[channel].output, data, data_len);
    xfree(data);
  } else {
    packet_get_all();
  }
}

/* Returns true if no channel has too much buffered data, and false if
   one or more channel is overfull. */

int channel_not_very_much_buffered_data()
{
#if 0
  unsigned int i;
  Channel *ch;
  
  for (i = 0; i < channels_alloc; i++)
    {
      ch = &channels[i];
      switch (channels[i].type)
	{
	case SSH_CHANNEL_X11_LISTENER:
	case SSH_CHANNEL_PORT_LISTENER:
	case SSH_CHANNEL_AUTH_LISTENER:
	  continue;
	case SSH_CHANNEL_OPEN:
	  if (buffer_len(&ch->input) > 32000)
	    return 0;
	  if (buffer_len(&ch->output) > 32000)
	    return 0;
	  continue;
	case SSH_CHANNEL_X11_OPEN:
	case SSH_CHANNEL_FREE:
	default:
	  continue;
	}
    }
#endif /* 0 */
  return 1;
}

#ifdef SUPPORT_OLD_CHANNELS
void channel_input_close_confirmation()
{
  if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
    channel_emulated_close(1);
  else
    channel_oclosed();
}

void channel_input_close()
{
  if (emulation_information & EMULATE_OLD_CHANNEL_CODE)
    channel_emulated_close(0);
  else
    channel_ieof();
}
#endif

/* This is called after receiving CHANNEL_OPEN_CONFIRMATION. */

void channel_input_open_confirmation()
{
  int channel, remote_channel;

  /* Get the channel number and verify it. */
  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type != SSH_CHANNEL_OPENING)
    packet_disconnect("Received open confirmation for non-opening channel %d.",
		      channel);
  
  /* Get remote side's id for this channel. */
  remote_channel = packet_get_int();

  /* Record the remote channel number and mark that the channel is now open. */
  debug("Channel now open, status bits %x", channels[channel].status_flags);
  channels[channel].remote_id = remote_channel;
  channels[channel].type = SSH_CHANNEL_OPEN;
}

/* This is called after receiving CHANNEL_OPEN_FAILURE from the other side. */

void channel_input_open_failure()
{
  int channel;

  /* Get the channel number and verify it. */
  channel = packet_get_int();
  if (channel < 0 || channel >= channels_alloc ||
      channels[channel].type != SSH_CHANNEL_OPENING)
    packet_disconnect("Received open failure for non-opening channel %d.",
		      channel);
  
  /* Free the channel.  This will also close the socket. */
  channel_free(channel);
}

/* Stops listening for channels, and removes any unix domain sockets that
   we might have. */

void channel_stop_listening()
{
  int i;
  for (i = 0; i < channels_alloc; i++)
    {
      switch (channels[i].type)
	{
	case SSH_CHANNEL_AUTH_LISTENER:
	  auth_delete_socket(NULL);
	  break;
	case SSH_CHANNEL_PORT_LISTENER:
	case SSH_CHANNEL_X11_LISTENER:
	  close(channels[i].sock);
	  channel_free(i);
	  break;
	default:
	  break;
	}
    }
}

/* Closes the sockets of all channels.  This is used to close extra file
   descriptors after a fork. */

void channel_close_all()
{
  int i;
  for (i = 0; i < channels_alloc; i++)
    {
      if (channels[i].type != SSH_CHANNEL_FREE)
	close(channels[i].sock);
    }
}

/* Returns the maximum file descriptor number used by the channels. */

int channel_max_fd()
{
  return channel_max_fd_value;
}

/* Returns true if any channel is still open. */

int channel_still_open()
{
  unsigned int i;
  for (i = 0; i < channels_alloc; i++)
    switch (channels[i].type)
      {
      case SSH_CHANNEL_FREE:
      case SSH_CHANNEL_X11_LISTENER:
      case SSH_CHANNEL_PORT_LISTENER:
      case SSH_CHANNEL_AUTH_LISTENER:
	continue;
      case SSH_CHANNEL_OPENING:
      case SSH_CHANNEL_OPEN:
      case SSH_CHANNEL_X11_OPEN:
	return 1;
      default:
	fatal("channel_still_open: bad channel type %d", channels[i].type);
	/*NOTREACHED*/
      }
  return 0;
}

/* Returns a message describing the currently open forwarded
   connections, suitable for sending to the client.  The message
   contains crlf pairs for newlines. */

char *channel_open_message()
{
  Buffer buffer;
  int i;
  char buf[512], *cp;

  buffer_init(&buffer);
  sprintf(buf, "The following connections are open:\r\n");
  buffer_append(&buffer, buf, strlen(buf));
  for (i = 0; i < channels_alloc; i++)
    switch (channels[i].type)
      {
      case SSH_CHANNEL_FREE:
      case SSH_CHANNEL_X11_LISTENER:
      case SSH_CHANNEL_PORT_LISTENER:
      case SSH_CHANNEL_AUTH_LISTENER:
	continue;
      case SSH_CHANNEL_OPENING:
      case SSH_CHANNEL_OPEN:
      case SSH_CHANNEL_X11_OPEN:
	sprintf(buf, "  %.300s\r\n", channels[i].remote_name);
	buffer_append(&buffer, buf, strlen(buf));
	continue;
      default:
	fatal("channel_still_open: bad channel type %d", channels[i].type);
	/*NOTREACHED*/
      }
  buffer_append(&buffer, "\0", 1);
  cp = xstrdup(buffer_ptr(&buffer));
  buffer_free(&buffer);
  return cp;
}

/* Initiate forwarding of connections to local port "port" through the secure
   channel to host:port from remote side. */

void channel_request_local_forwarding(int port, const char *host,
				      int host_port)
{
  int ch, sock;
  struct sockaddr_in sin;

  if (strlen(host) > sizeof(channels[0].path) - 1)
    packet_disconnect("Forward host name too long.");
  
  /* Create a port to listen for the host. */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    packet_disconnect("socket: %.100s", strerror(errno));

#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(sock, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(sock, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

  /* Initialize socket address. */
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port);
  
  /* Bind the socket to the address. */
  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    packet_disconnect("bind: %.100s", strerror(errno));
      
  /* Start listening for connections on the socket. */
  if (listen(sock, 5) < 0)
    packet_disconnect("listen: %.100s", strerror(errno));
	    
  /* Allocate a channel number for the socket. */
  ch = channel_allocate(SSH_CHANNEL_PORT_LISTENER, sock,
			xstrdup("port listener"));
  strcpy(channels[ch].path, host); /* note: host name stored here */
  channels[ch].host_port = host_port; /* port on host to connect to */
  channels[ch].listening_port = port; /* port being listened */
}  

/* Initiate forwarding of connections to port "port" on remote host through
   the secure channel to host:port from local side. */

void channel_request_remote_forwarding(int port, const char *host,
				       int remote_port)
{
  int type;
  
  /* Send the forward request to the remote side. */
  packet_start(SSH_CMSG_PORT_FORWARD_REQUEST);
  packet_put_int(port);
  packet_put_string(host, strlen(host));
  packet_put_int(remote_port);
  packet_send();
  packet_write_wait();
  
  /* Wait for response from the remote side.  It will send a disconnect
     message on failure, and we will never see it here. */
  type = packet_read();
  if (type == SSH_SMSG_FAILURE)
    {
      debug("Remote end denied port forwarding to %d:%.50s:%d",
	    port, host, remote_port);
      return;
    }
  if (type != SSH_SMSG_SUCCESS)
    packet_disconnect("Protocol error: expected packet type %d, got %d",
		      SSH_SMSG_SUCCESS, type);
  
  /* Record locally that connection to this host/port is permitted. */
  if (num_permitted_opens >= SSH_MAX_FORWARDS_PER_DIRECTION)
    fatal("channel_request_remote_forwarding: too many forwards");
  permitted_opens[num_permitted_opens].host = xstrdup(host);
  permitted_opens[num_permitted_opens].port = remote_port;
  num_permitted_opens++;
}

/* This is called after receiving CHANNEL_FORWARDING_REQUEST.  This initates
   listening for the port, and sends back a success reply (or disconnect
   message if there was an error).  This never returns if there was an 
   error. */

void channel_input_port_forward_request(int is_root)
{
  int port, host_port;
  char *hostname;
  
  /* Get arguments from the packet. */
  port = packet_get_int();
  hostname = packet_get_string(NULL);
  host_port = packet_get_int();

  if (strlen(hostname) > 255)
    packet_disconnect("Requested forwarding hostname too long: %.200s.",
		      hostname);
  
  /* Check that an unprivileged user is not trying to forward a privileged
     port. */
  if (port < 1024 && !is_root)
    packet_disconnect("Requested forwarding of port %d but user is not root.",
		      port);

  /* Initiate forwarding. */
  channel_request_local_forwarding(port, hostname, host_port);

  /* Free the argument string. */
  xfree(hostname);
}

/* This is called after receiving PORT_OPEN message.  This attempts to connect
   to the given host:port, and sends back CHANNEL_OPEN_CONFIRMATION or
   CHANNEL_OPEN_FAILURE. */

void channel_input_port_open()
{
  int remote_channel, sock, newch, host_port, i;
  struct sockaddr_in sin;
  char *host, *originator_string;
  struct hostent *hp;

  /* Get remote channel number. */
  remote_channel = packet_get_int();

  /* Get host name to connect to. */
  host = packet_get_string(NULL);

  if (strlen(host) > 255)
    packet_disconnect("Requested forwarding hostname too long: %.200s.",
		      host);
  
  /* Get port to connect to. */
  host_port = packet_get_int();

  /* Get remote originator name. */
  if (have_hostname_in_open)
    originator_string = packet_get_string(NULL);
  else
    originator_string = xstrdup("unknown (remote did not supply name)");

  /* Check if opening that port is permitted. */
  if (!all_opens_permitted)
    {
      /* Go trough all permitted ports. */
      for (i = 0; i < num_permitted_opens; i++)
	if (permitted_opens[i].port == host_port &&
	    strcmp(permitted_opens[i].host, host) == 0)
	  break;

      /* Check if we found the requested port among those permitted. */
      if (i >= num_permitted_opens)
	{
	  /* The port is not permitted. */
	  log_msg("Received request to connect to %.100s:%d, but the request was denied.",
	      host, host_port);
	  packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
	  packet_put_int(remote_channel);
	  packet_send();
	}
    }
  
  memset(&sin, 0, sizeof(sin));
#ifdef BROKEN_INET_ADDR
  sin.sin_addr.s_addr = inet_network(host);
#else /* BROKEN_INET_ADDR */
  sin.sin_addr.s_addr = inet_addr(host);
#endif /* BROKEN_INET_ADDR */
  if ((sin.sin_addr.s_addr & 0xffffffff) != 0xffffffff)
    {
      /* It was a valid numeric host address. */
      sin.sin_family = AF_INET;
    }
  else
    {
      /* Look up the host address from the name servers. */
      hp = gethostbyname(host);
      if (!hp)
	{
	  error("%.100s: unknown host.", host);
	  goto fail;
	}
      if (!hp->h_addr_list[0])
	{
	  error("%.100s: host has no IP address.", host);
	  goto fail;
	}
      sin.sin_family = hp->h_addrtype;
      memcpy(&sin.sin_addr, hp->h_addr_list[0], 
	     sizeof(sin.sin_addr));
    }
  sin.sin_port = htons(host_port);

  /* Create the socket. */
  sock = socket(sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0)
    {
      error("socket: %.100s", strerror(errno));
      goto fail;
    }

  /* Connect to the host/port. */
  if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
      error("connect %.100s:%d: %.100s", host, host_port,
	    strerror(errno));
      close(sock);
      goto fail;
    }

  /* Successful connection. */

#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(sock, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(sock, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

  /* Allocate a channel for this connection. */
  newch = channel_allocate(SSH_CHANNEL_OPEN, sock, originator_string);
  channels[newch].remote_id = remote_channel;
  
  /* Send a confirmation to the remote host. */
  packet_start(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  packet_put_int(remote_channel);
  packet_put_int(newch);
  packet_send();

  /* Free the argument string. */
  xfree(host);
  
  return;

 fail:
  /* Free the argument string. */
  xfree(host);

  /* Send refusal to the remote host. */
  packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
  packet_put_int(remote_channel);
  packet_send();
}

/* Creates an internet domain socket for listening for X11 connections. 
   Returns a suitable value for the DISPLAY variable, or NULL if an error
   occurs. */

char *x11_create_display_inet(int screen_number)
{
  extern ServerOptions options;
  int display_number, port, sock;
  struct sockaddr_in sin;
  char buf[512];
#ifdef HAVE_GETHOSTNAME
  char hostname[257];
#else
  struct utsname uts;
#endif

  /* open first vacant display, starting at an offset (default 1) so
   * as not to clobber the low numbers. (Modification by Jari Kokko)
   */
  for (display_number = options.x11_display_offset; display_number < MAX_DISPLAYS; display_number++)
    {
      port = 6000 + display_number;
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = INADDR_ANY;
      sin.sin_port = htons(port);
      
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock < 0)
	{
	  error("socket: %.100s", strerror(errno));
	  return NULL;
	}

#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
      (void)fcntl(sock, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
      (void)fcntl(sock, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
      
      if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
	  debug("bind port %d: %.100s", port, strerror(errno));
	  shutdown(sock, 2);
	  close(sock);
	  continue;
	}
      break;
    }
  if (display_number >= MAX_DISPLAYS)
    {
      error("Failed to allocate internet-domain X11 display socket.");
      return NULL;
    }

  /* Start listening for connections on the socket. */
  if (listen(sock, 5) < 0)
    {
      error("listen: %.100s", strerror(errno));
      shutdown(sock, 2);
      close(sock);
      return NULL;
    }

  /* Set up a suitable value for the DISPLAY variable. */
#ifdef HPSUX_NONSTANDARD_X11_KLUDGE
  /* HPSUX has some special shared memory stuff in their X server, which
     appears to be enabled if the host name matches that of the local machine.
     However, it can be circumvented by using the IP address of the local
     machine instead.  */
  if (gethostname(hostname, sizeof(hostname)) < 0)
    fatal("gethostname: %.100s", strerror(errno));
  {
    struct hostent *hp;
    struct in_addr addr;
    hp = gethostbyname(hostname);
    if (hp == NULL || !hp->h_addr_list[0])
      {
	error("Could not get server IP address for %.200s.", hostname);
	packet_send_debug("Could not get server IP address for %.200s.", 
			  hostname);
	shutdown(sock, 2);
	close(sock);
	return NULL;
      }
    memcpy(&addr, hp->h_addr_list[0], sizeof(addr));
    sprintf(buf, "%.100s:%d.%d", inet_ntoa(addr), display_number, 
	    screen_number);
  }
#else /* HPSUX_NONSTANDARD_X11_KLUDGE */
#ifdef HAVE_GETHOSTNAME
  if (gethostname(hostname, sizeof(hostname)) < 0)
    fatal("gethostname: %.100s", strerror(errno));
  sprintf(buf, "%.400s:%d.%d", hostname, display_number, screen_number);
#else /* HAVE_GETHOSTNAME */
  if (uname(&uts) < 0)
    fatal("uname: %s", strerror(errno));
  sprintf(buf, "%.400s:%d.%d", uts.nodename, display_number, screen_number);
#endif /* HAVE_GETHOSTNAME */
#endif /* HPSUX_NONSTANDARD_X11_KLUDGE */
	    
  /* Allocate a channel for the socket. */
  (void)channel_allocate(SSH_CHANNEL_X11_LISTENER, sock,
			 xstrdup("X11 inet listener"));

  /* Return a suitable value for the DISPLAY environment variable. */
  return xstrdup(buf);
}

/* This is called when SSH_SMSG_X11_OPEN is received.  The packet contains
   the remote channel number.  We should do whatever we want, and respond
   with either SSH_MSG_OPEN_CONFIRMATION or SSH_MSG_OPEN_FAILURE. */

void x11_input_open()
{
  int remote_channel, display_number, sock, newch;
  const char *display;
  struct sockaddr_un ssun;
  struct sockaddr_in sin;
  char buf[255], *cp, *remote_host;
  struct hostent *hp;

  /* Get remote channel number. */
  remote_channel = packet_get_int();

  /* Get remote originator name. */
  if (have_hostname_in_open)
    remote_host = packet_get_string(NULL);
  else
    remote_host = xstrdup("unknown (remote did not supply name)");

  debug("Received X11 open request.");

  if (!x11_forwarding_permitted)
    {
      error("Warning: Server attempted X11 forwarding without client request");
      error("Warning: This is a probable break-in attempt (compromised server?)");
      goto fail;
    }
  

  /* Try to open a socket for the local X server. */
  display = getenv("DISPLAY");
  if (!display)
    {
      error("DISPLAY not set.");
      goto fail;
    }
  
  /* Now we decode the value of the DISPLAY variable and make a connection
     to the real X server. */

  /* Check if it is a unix domain socket.  Unix domain displays are in one
     of the following formats: unix:d[.s], :d[.s], ::d[.s] */
  if (strncmp(display, "unix:", 5) == 0 ||
      display[0] == ':')
    {
      /* Connect to the unix domain socket. */
      if (sscanf(strrchr(display, ':') + 1, "%d", &display_number) != 1)
	{
	  error("Could not parse display number from DISPLAY: %.100s",
		display);
	  goto fail;
	}
      /* Create a socket. */
      sock = socket(AF_UNIX, SOCK_STREAM, 0);
      if (sock < 0)
	{
	  error("socket: %.100s", strerror(errno));
	  goto fail;
	}
      /* Connect it to the display socket. */
      ssun.sun_family = AF_UNIX;
#ifdef HPSUX_NONSTANDARD_X11_KLUDGE
      {
	/* HPSUX release 10.X uses /var/spool/sockets/X11/0 for the
	   unix-domain sockets, while earlier releases stores the
	   socket in /usr/spool/sockets/X11/0 with soft-link from
	   /tmp/.X11-unix/`uname -n`0 */

	struct stat st;

	if (stat("/var/spool/sockets/X11", &st) == 0)
	  {
	    sprintf(ssun.sun_path, "%s/%d",
		    "/var/spool/sockets/X11", display_number);
	  }
	else
	  {
	    if (stat("/usr/spool/sockets/X11", &st) == 0)
	      {
		sprintf(ssun.sun_path, "%s/%d",
			"/usr/spool/sockets/X11", display_number);
	      }
	    else
	      {
		struct utsname utsbuf;
		/* HPSUX stores unix-domain sockets in
		   /tmp/.X11-unix/`hostname`0 
		   instead of the normal /tmp/.X11-unix/X0. */
		if (uname(&utsbuf) < 0)
		  fatal("uname: %.100s", strerror(errno));
		sprintf(ssun.sun_path, "%.20s/%.64s%d",
			X11_DIR, utsbuf.nodename, display_number);
	      }
	  }
      }
#else /* HPSUX_NONSTANDARD_X11_KLUDGE */
      sprintf(ssun.sun_path, "%.80s/X%d", X11_DIR, display_number);
#endif /* HPSUX_NONSTANDARD_X11_KLUDGE */
      if (connect(sock, (struct sockaddr *)&ssun, AF_UNIX_SIZE(ssun)) < 0)
	{
	  error("connect %.100s: %.100s", ssun.sun_path, strerror(errno));
	  close(sock);
	  goto fail;
	}

      /* OK, we now have a connection to the display. */
      goto success;
    }
  
  /* Connect to an inet socket.  The DISPLAY value is supposedly
      hostname:d[.s], where hostname may also be numeric IP address. */
  strncpy(buf, display, sizeof(buf));
  buf[sizeof(buf) - 1] = 0;
  cp = strchr(buf, ':');
  if (!cp)
    {
      error("Could not find ':' in DISPLAY: %.100s", display);
      goto fail;
    }
  *cp = 0;
  /* buf now contains the host name.  But first we parse the display number. */
  if (sscanf(cp + 1, "%d", &display_number) != 1)
    {
       error("Could not parse display number from DISPLAY: %.100s",
	     display);
      goto fail;
    }
  
  /* Try to parse the host name as a numeric IP address. */
  memset(&sin, 0, sizeof(sin));
#ifdef BROKEN_INET_ADDR
  sin.sin_addr.s_addr = inet_network(buf);
#else /* BROKEN_INET_ADDR */
  sin.sin_addr.s_addr = inet_addr(buf);
#endif /* BROKEN_INET_ADDR */
  if ((sin.sin_addr.s_addr & 0xffffffff) != 0xffffffff)
    {
      /* It was a valid numeric host address. */
      sin.sin_family = AF_INET;
    }
  else
    {
      /* Not a numeric IP address. */
      /* Look up the host address from the name servers. */
      hp = gethostbyname(buf);
      if (!hp)
	{
	  error("%.100s: unknown host.", buf);
	  goto fail;
	}
      if (!hp->h_addr_list[0])
	{
	  error("%.100s: host has no IP address.", buf);
	  goto fail;
	}
      sin.sin_family = hp->h_addrtype;
      memcpy(&sin.sin_addr, hp->h_addr_list[0], 
	     sizeof(sin.sin_addr));
    }
  /* Set port number. */
  sin.sin_port = htons(6000 + display_number);

  /* Create a socket. */
  sock = socket(sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0)
    {
      error("socket: %.100s", strerror(errno));
      goto fail;
    }
  /* Connect it to the display. */
  if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
      error("connect %.100s:%d: %.100s", buf, 6000 + display_number, 
	    strerror(errno));
      close(sock);
      goto fail;
    }

 success:
  /* We have successfully obtained a connection to the real X display. */

#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
      (void)fcntl(sock, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
      (void)fcntl(sock, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  
  /* Allocate a channel for this connection. */
  if (x11_saved_proto == NULL)
    newch = channel_allocate(SSH_CHANNEL_OPEN, sock, remote_host);
  else
    newch = channel_allocate(SSH_CHANNEL_X11_OPEN, sock, remote_host);
  channels[newch].is_x_connection = 1;
  channels[newch].remote_id = remote_channel;
  
  debug("Sending open confirmation to the remote host.");

  /* Send a confirmation to the remote host. */
  packet_start(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  packet_put_int(remote_channel);
  packet_put_int(newch);
  packet_send();
  
  return;

 fail:
  debug ("Failed...");
  /* Send refusal to the remote host. */
  packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
  packet_put_int(remote_channel);
  packet_send();
}

/* Requests forwarding of X11 connections, generates fake authentication
   data, and enables authentication spoofing. */

void x11_request_forwarding_with_spoofing(RandomState *state,
					  const char *proto, const char *data)
{
  unsigned int data_len = (unsigned int)strlen(data) / 2;
  unsigned int i, value;
  char *new_data;
  int screen_number;
  const char *cp;

  cp = getenv("DISPLAY");
  if (cp)
    cp = strchr(cp, ':');
  if (cp)
    cp = strchr(cp, '.');
  if (cp)
    screen_number = atoi(cp + 1);
  else
    screen_number = 0;

  /* Save protocol name. */
  x11_saved_proto = xstrdup(proto);

  /* Extract real authentication data and generate fake data of the same
     length. */
  x11_saved_data = xmalloc(data_len);
  x11_fake_data = xmalloc(data_len);
  for (i = 0; i < data_len; i++)
    {
      if (sscanf(data + 2 * i, "%2x", &value) != 1)
	fatal("x11_request_forwarding: bad authentication data: %.100s", data);
      x11_saved_data[i] = value;
      x11_fake_data[i] = random_get_byte(state);
    }
  x11_saved_data_len = data_len;
  x11_fake_data_len = data_len;

  /* Convert the fake data into hex. */
  new_data = xmalloc(2 * data_len + 1);
  for (i = 0; i < data_len; i++)
    sprintf(new_data + 2 * i, "%02x", (unsigned char)x11_fake_data[i]);

  /* Send the request packet. */
  packet_start(SSH_CMSG_X11_REQUEST_FORWARDING);
  packet_put_string(proto, strlen(proto));
  packet_put_string(new_data, strlen(new_data));
  packet_put_int(screen_number);
  packet_send();
  packet_write_wait();
  xfree(new_data);
  x11_forwarding_permitted = 1;
}

/* Sends a message to the server to request authentication fd forwarding. */

void auth_request_forwarding()
{
  packet_start(SSH_CMSG_AGENT_REQUEST_FORWARDING);
  packet_send();
  packet_write_wait();
  auth_forwarding_permitted = 1;
}

/* Returns the number of the file descriptor to pass to child programs as
   the authentication fd.  Returns -1 if there is no forwarded authentication
   fd. */

int auth_get_fd()
{
  return channel_forwarded_auth_fd;
}

/* Returns the name of the forwarded authentication socket.  Returns NULL
   if there is no forwarded authentication socket.  The returned value
   points to a static buffer. */

char *auth_get_socket_name()
{
  return channel_forwarded_auth_socket_name;
}

/* Called on exit, tries to remove authentication socket and per-user
   socket directory */

void auth_delete_socket(void *context)
{
  if (channel_forwarded_auth_socket_name)
    {
      remove(channel_forwarded_auth_socket_name);
      xfree(channel_forwarded_auth_socket_name);
      channel_forwarded_auth_socket_name = NULL;
    }
  if (channel_forwarded_auth_socket_dir_name)
    {
      chdir("/");
      rmdir(channel_forwarded_auth_socket_dir_name);
      xfree(channel_forwarded_auth_socket_dir_name);
      channel_forwarded_auth_socket_dir_name = NULL;
    }
}

/* This if called to process SSH_CMSG_AGENT_REQUEST_FORWARDING on the server.
   This starts forwarding authentication requests.
   Socket directory will be owned by the user, and will have 700-
   permissions. Actual socket will have 222-permissions and can be
   owned by anyone (sshd's socket will be owned by root and
   ssh-agent's by user). This returns true if everything succeeds, otherwise it
   will return false (agent forwarding disabled). */

int auth_input_request_forwarding(struct passwd *pw)
{
  int ret;
  int sock, newch, directory_created;
  struct sockaddr_un sunaddr;
  struct stat st, st2, parent_st;
  mode_t old_umask;
  char *last_dir;
  
  if (auth_get_socket_name() != NULL)
    fatal("Protocol error: authentication forwarding requested twice.");
  
  /* Allocate a buffer for the socket name, and format the name.
     And directory name. */
  channel_forwarded_auth_socket_name = xmalloc(strlen(SSH_AGENT_SOCKET_DIR) +
					       strlen(SSH_AGENT_SOCKET) +
					       strlen(pw->pw_name) + 10);
  channel_forwarded_auth_socket_dir_name =
    xmalloc(strlen(SSH_AGENT_SOCKET_DIR) +
	    strlen(pw->pw_name) + 10);

  sprintf(channel_forwarded_auth_socket_dir_name, 
	  SSH_AGENT_SOCKET_DIR, pw->pw_name);
  /* Use the plain socket name for now, change to absolute
     path later */
  sprintf(channel_forwarded_auth_socket_name,
	  SSH_AGENT_SOCKET, (int)getpid());
  
  /* Register the cleanup function before making the directory */
  fatal_add_cleanup(&auth_delete_socket, NULL);

  /* Stat parent dir */
  last_dir = strrchr(channel_forwarded_auth_socket_dir_name, '/');
  if (last_dir == NULL || last_dir == channel_forwarded_auth_socket_dir_name)
    {
      packet_send_debug("* Remote error: Invalid SSH_AGENT_SOCKET_DIR \'%.100s\', it should contain at least one /.",
	    channel_forwarded_auth_socket_dir_name);
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  *last_dir = '\0';
  ret = stat(channel_forwarded_auth_socket_dir_name, &parent_st);
  if (ret < 0)
    {
      packet_send_debug("* Remote error: Agent parent directory \'%.100s\' stat failed: %.100s",
	    channel_forwarded_auth_socket_dir_name, 
	    strerror(errno));
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  *last_dir = '/';
  
  /* Check the per-user socket directory. Stat it, if it
     doesn't exist, mkdir it and stat it. Then chdir to it
     and stat "." and compare it with the earlier stat (dev
     and inode) so that we can be sure we ended where we
     wanted. Then stat ".." and check that it is sticky.
     Only after this we can think about chowning the ".". */
  
  ret = lstat(channel_forwarded_auth_socket_dir_name, &st);
  directory_created = 0;
  if (ret < 0 && errno != ENOENT)
    {
      packet_send_debug("* Remote error: stat of agent directory \'%.100s\' failed: %.100s",
	    channel_forwarded_auth_socket_dir_name,
	    strerror(errno));
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  if (ret < 0 && errno == ENOENT)
    {
      if (mkdir(channel_forwarded_auth_socket_dir_name, S_IRWXU) == 0)
	{
	  directory_created = 1;
	  ret = lstat(channel_forwarded_auth_socket_dir_name, &st);
	}
      else
	{
	  packet_send_debug("* Remote error: Agent directory \'%.100s\' mkdir failed: %.100s",
		channel_forwarded_auth_socket_dir_name,
		strerror(errno));
	  packet_send_debug("* Remote error: Authentication fowarding disabled.");
	  return 0;
	}
    }
  else
    {
      /* Simple owner & mode check. If directory has just been created,
	 don't care about the owner yet. */
      if ((st.st_uid != pw->pw_uid) || (st.st_mode & 077) != 0)
	{
	  packet_send_debug("* Remote error: Agent socket creation:"
		"Bad modes/owner for directory \'%s\' (modes are %o, should be 041777)",
		channel_forwarded_auth_socket_dir_name,
		st.st_mode);
	  packet_send_debug("* Remote error: Authentication fowarding disabled.");
	  return 0;
	}
    }
  chdir(channel_forwarded_auth_socket_dir_name);
  
  /* Check that we really are where we wanted to go */
  if (stat(".", &st2) != 0)
    {
      packet_send_debug("* Remote error: stat \'.\' failed after chdir to \'%.100s\': %.100s",
	    channel_forwarded_auth_socket_dir_name, strerror(errno));
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  if (st.st_dev != st2.st_dev || st.st_ino != st2.st_ino)
    {
      packet_send_debug("* Remote error: Agent socket creation: wrong directory after chdir");
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }

  /* Check that parent is sticky, and it really is what it is supposed to be */
  if (stat("..", &st) != 0)
    {
      packet_send_debug("* Remote error: Agent socket directory stat \'..\' failed: %.100s",
	    strerror(errno));
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  if ((st.st_mode & 01000) == 0)
    {
      packet_send_debug("* Remote error: Agent socket creation: Directory \'%s/..\' is not sticky, mode is %o, should be 041777",
	    channel_forwarded_auth_socket_dir_name, st.st_mode);
      packet_send_debug("* Remote error: Authentication forwarding disabled.");
      return 0;
    }
  if (st.st_dev != parent_st.st_dev || st.st_ino != parent_st.st_ino)
    {
      packet_send_debug("* Remote error: Agent socket creation: wrong parent directory after chdir (last component of socket name is symlink?)");
      packet_send_debug("* Remote error: Authentication fowarding disabled.");
      return 0;
    }
  
  /* Create the socket. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    packet_disconnect("Agent socket creation failed: %.100s", strerror(errno));
  
  /* Bind it to the name. */
  memset(&sunaddr, 0, AF_UNIX_SIZE(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, channel_forwarded_auth_socket_name, 
	  sizeof(sunaddr.sun_path));
  
  /* Use umask to get desired permissions, chmod is too dangerous
     NOTE: If your system doesn't handle umask correctly when
     creating unix-domain sockets, you might not be able to use
     ssh-agent connections on your system */
  old_umask = umask(S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
  
  if (bind(sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr)) < 0)
    packet_disconnect("Agent socket bind failed: %.100s", strerror(errno));
  
  umask(old_umask);
  
  if (directory_created)
    chown(".", pw->pw_uid, pw->pw_gid);

  /* Start listening on the socket. */
  if (listen(sock, 5) < 0)
    packet_disconnect("Agent socket listen failed: %.100s", strerror(errno));

  /* Change the relative socket name to absolute */
  sprintf(channel_forwarded_auth_socket_name, 
	  SSH_AGENT_SOCKET_DIR"/"SSH_AGENT_SOCKET,
	  pw->pw_name, (int)getpid());
    
  /* Allocate a channel for the authentication agent socket. */
  newch = channel_allocate(SSH_CHANNEL_AUTH_LISTENER, sock,
			   xstrdup("auth socket"));
  strcpy(channels[newch].path, channel_forwarded_auth_socket_name);
  return 1;
}

/* This is called to process an SSH_SMSG_AGENT_OPEN message. */

void auth_input_open_request()
{
  int remote_channel, sock, newch;
  char *dummyname;

  /* Read the port number from the message. */
  remote_channel = packet_get_int();

  if (!auth_forwarding_permitted)
    {
      error("Warning: Server attempted agent forwarding without client request");
      error("Warning: This is a probable break-in attempt (compromised server?)");
      packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
      packet_put_int(remote_channel);
      packet_send();
      return;
    }
  /* Get a connection to the local authentication agent (this may again get
     forwarded). */
  sock = ssh_get_authentication_connection_fd();

  /* If we could not connect the agent, inform the server side that
     opening failed. This should never happen unless the agent
     dies, because authentication forwarding is only enabled if we
     have an agent. */
  if (sock < 0)
    {
      packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
      packet_put_int(remote_channel);
      packet_send();
      return;
    }
  
  debug("Forwarding authentication connection.");

  dummyname = xstrdup("authentication agent connection");
  
  /* Allocate a channel for this connection. */
  newch = channel_allocate(SSH_CHANNEL_OPEN, sock, dummyname);
  channels[newch].remote_id = remote_channel;
  
  /* Send a confirmation to the remote host. */
  packet_start(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  packet_put_int(remote_channel);
  packet_put_int(newch);
  packet_send();
}
