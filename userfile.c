/*

userfile.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Jan 24 20:19:53 1996 ylo

*/

/*
 * $Log: userfile.c,v $
 * Revision 1.15  1997/03/26 07:10:04  kivinen
 * 	Changed uid 0 to UID_ROOT.
 *
 * Revision 1.14  1997/03/25 05:47:00  kivinen
 * 	Changed USERFILE_GET_DES_1_MAGIC_PHRASE to call
 * 	userfile_get_des_1_magic_phrase.
 *
 * Revision 1.13  1997/03/19 17:53:46  kivinen
 * 	Added USERFILE_GET_DES_1_MAGIC_PHRASE.
 *
 * Revision 1.12  1996/11/27 14:30:07  ttsalo
 *     Added group-writeability #ifdef
 *
 * Revision 1.11  1996/10/29 22:48:23  kivinen
 * 	Removed USERFILE_LOCAL_SOCK and USERFILE_SEND.
 *
 * Revision 1.10  1996/10/07 11:40:20  ttsalo
 * 	Configuring for hurd and a small fix to do_popen()
 * 	from "Charles M. Hannum" <mycroft@gnu.ai.mit.edu> added.
 *
 * Revision 1.9  1996/10/04 01:01:49  kivinen
 * 	Added printing of path to fatal calls in userfile_open and and
 * 	userfile_local_socket_connect. Fixed userfile_open to
 * 	userfile_local_socket_connect in calls to fatal in
 * 	userfile_local_socket_connect.
 *
 * Revision 1.8  1996/09/27 17:18:06  ylo
 * 	Fixed a typo.
 *
 * Revision 1.7  1996/09/08 17:21:08  ttsalo
 * 	A lot of changes in agent-socket handling
 *
 * Revision 1.6  1996/09/04 12:39:59  ttsalo
 * 	Added connecting to unix-domain socket
 *
 * Revision 1.5  1996/08/13 09:04:19  ttsalo
 * 	Home directory, .ssh and .ssh/authorized_keys are now
 * 	checked for wrong owner and group & world writeability.
 *
 * Revision 1.4  1996/05/29 07:37:31  ylo
 * 	Do setgid and initgroups when initializing to read as user.
 *
 * Revision 1.3  1996/04/26 18:10:45  ylo
 * 	Wrong file descriptors were closed in the forked child in
 * 	do_popen.  This caused dup2 to fail on some machines, which in
 * 	turn resulted in X11 authentication failing on some machines.
 *
 * Revision 1.2  1996/02/18 21:48:46  ylo
 * 	Close pipes after popen fork.
 * 	New function userfile_close_pipes.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:11  ylo
 * 	Imported ssh-1.2.13.
 *
 * $EndLog$
 */

/* Protocol for communication between the child and the parent: 

      Each message starts with a 32-bit length (msb first; includes
      type but not length itself), followed by one byte containing
      the packet type.

	1 USERFILE_OPEN
          string 	file name
	  int32 	flags
	  int32		mode

	2 USERFILE_OPEN_REPLY
	  int32		handle (-1 if error)

	3 USERFILE_READ
	  int32		handle
	  int32		max_bytes

        4 USERFILE_READ_REPLY
	  string	data	  ;; empty data means EOF

	5 USERFILE_WRITE
	  int32		handle
	  string	data

	6 USERFILE_WRITE_REPLY
	  int32		bytes_written  ;; != length of data means error
	
	7 USERFILE_CLOSE
	  int32		handle

	8 USERFILE_CLOSE_REPLY
	  int32		return value

	9 USERFILE_LSEEK
	  int32		handle
	  int32		offset
	  int32		whence

       10 USERFILE_LSEEK_REPLY
	  int32 	returned_offset

       11 USERFILE_MKDIR
	  string	path
	  int32		mode

       12 USERFILE_MKDIR_REPLY
	  int32		return value

       13 USERFILE_STAT
	  string	path

       14 USERFILE_STAT_REPLY
          int32		return value
	  sizeof(struct stat) binary bytes (in host order and layout)

       15 USERFILE_REMOVE
	  string	path

       16 USERFILE_REMOVE_REPLY
	  int32		return value

       17 USERFILE_POPEN
	  string	command
	  string	type

       18 USERFILE_POPEN_REPLY
	  int32		handle (-1 if error)

       19 USERFILE_PCLOSE
          int32		handle

       20 USERFILE_PCLOSE_REPLY
	  int32		return value

       21 USERFILE_GET_DES_1_MAGIC_PHRASE

       22 USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY
	  string	data
	  
	  */

#include "includes.h"
#include <gmp.h>
#include "userfile.h"
#include "getput.h"
#include "buffer.h"
#include "bufaux.h"
#include "xmalloc.h"
#include "ssh.h"

#ifdef SECURE_RPC
#include <rpc/rpc.h>
#endif


/* Protocol message types. */
#define USERFILE_OPEN		1
#define USERFILE_OPEN_REPLY	2
#define USERFILE_READ		3
#define USERFILE_READ_REPLY	4
#define USERFILE_WRITE		5
#define USERFILE_WRITE_REPLY	6
#define USERFILE_CLOSE		7
#define USERFILE_CLOSE_REPLY	8
#define USERFILE_LSEEK		9
#define USERFILE_LSEEK_REPLY   10
#define USERFILE_MKDIR	       11
#define USERFILE_MKDIR_REPLY   12
#define USERFILE_STAT	       13
#define USERFILE_STAT_REPLY    14
#define USERFILE_REMOVE	       15
#define USERFILE_REMOVE_REPLY  16
#define USERFILE_POPEN	       17
#define USERFILE_POPEN_REPLY   18
#define USERFILE_PCLOSE	       19
#define USERFILE_PCLOSE_REPLY  20
#define USERFILE_GET_DES_1_MAGIC_PHRASE	       21
#define USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY  22


/* Flag indicating whether we have forked. */
static int userfile_initialized = 0;

/* The uid under which the child is running. */
static uid_t userfile_uid = -1;

/* Communication pipes. */
static int userfile_tochild;
static int userfile_fromchild;
static int userfile_toparent;
static int userfile_fromparent;

/* Aliases to above; set up depending on whether running as the server or
   the child. */
static int userfile_output;
static int userfile_input;

/* Buffer for a packet. */
static Buffer packet;
static int packet_initialized = 0;

/* Starts constructing a packet.  Stores the type into the packet. */

static void userfile_packet_start(int type)
{
  if (!packet_initialized)
    {
      buffer_init(&packet);
      packet_initialized = 1;
    }
  
  buffer_clear(&packet);
  buffer_put_char(&packet, type);
}

/* Sends a packet that has been constructed in "packet". */
  
static void userfile_packet_send()
{
  unsigned char lenbuf[4];
  unsigned int len, offset;
  int bytes;

  len = buffer_len(&packet);
  PUT_32BIT(lenbuf, len);
  len = 4;
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = write(userfile_output, lenbuf + offset, len - offset);
      if (bytes <= 0)
	fatal("userfile_packet_send: child has died: %s", strerror(errno));
    }
  
  len = buffer_len(&packet);
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = write(userfile_output, buffer_ptr(&packet) + offset, 
		    len - offset);
      if (bytes <= 0)
	fatal("userfile_packet_send: child has died: %s", strerror(errno));
    }
}

/* Reads a packet from the other side.  Returns the packet type. */

static int userfile_read_raw()
{
  unsigned char buf[512];
  unsigned int len, offset;
  int bytes;

  if (!packet_initialized)
    {
      buffer_init(&packet);
      packet_initialized = 1;
    }

  len = 4;
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = read(userfile_input, buf + offset, len - offset);
      if (bytes <= 0)
	{
	  if (getuid() == geteuid()) /* presumably child - be quiet */
	    exit(0);
	  fatal("userfile_read_raw: child has died: %s", strerror(errno));
	}
    }

  len = GET_32BIT(buf);
  if (len > 32000)
    fatal("userfile_read_raw: received packet too long.");
  
  buffer_clear(&packet);
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = len - offset;
      if (bytes > sizeof(buf))
	bytes = sizeof(buf);
      bytes = read(userfile_input, buf, bytes);
      if (bytes <= 0)
	fatal("userfile_read_raw: child has died: %s", strerror(errno));
      buffer_append(&packet, buf, bytes);
    }
  return buffer_get_char(&packet);
}

/* Reads a packet from the child.  The packet should be of expected_type. */

static void userfile_packet_read(int expected_type)
{
  int type;

  type = userfile_read_raw();
  if (type != expected_type)
    fatal("userfile_read_packet: unexpected packet type: got %d, expected %d",
	  type, expected_type);
}

/* Forks and execs the given command.  Returns a file descriptor for
   communicating with the program, or -1 on error.  The program will
   be run with empty environment to avoid LD_LIBRARY_PATH and similar
   attacks. */

int do_popen(const char *command, const char *type)
{
  int fds[2];
  int pid, i, j;
  char *args[100];
  char *env[100];
  extern char **environ;
  
  if (pipe(fds) < 0)
    fatal("pipe: %s", strerror(errno));
  
  pid = fork();
  if (pid < 0)
    fatal("fork: %s", strerror(errno));
  
  if (pid == 0)
    { /* Child */

      /* Close pipes to the parent; we do not wish to disclose them to a
	 random user program. */
      close(userfile_fromparent);
      close(userfile_toparent);

      /* Set up file descriptors. */
      if (type[0] == 'r')
	{
	  if (dup2(fds[1], 1) < 0)
	    perror("dup2 1");
	}
      else
	{
	  if (dup2(fds[0], 0) < 0)
	    perror("dup2 0");
	}
      close(fds[0]);
      close(fds[1]);

      /* Build argument vector. */
      i = 0;
      args[i++] = "/bin/sh";
      args[i++] = "-c";
      args[i++] = (char *)command;
      args[i++] = NULL;

      /* Prune environment to remove any potentially dangerous variables. */
      i = 0;
      for (j = 0; environ[j] && i < sizeof(env)/sizeof(env[0]) - 1; j++)
	if (strncmp(environ[j], "HOME=", 5) == 0 ||
	    strncmp(environ[j], "USER=", 5) == 0 ||
	    strncmp(environ[j], "HOME=", 5) == 0 ||
	    strncmp(environ[j], "PATH=", 5) == 0 ||
	    strncmp(environ[j], "LOGNAME=", 8) == 0 ||
	    strncmp(environ[j], "TZ=", 3) == 0 ||
	    strncmp(environ[j], "MAIL=", 5) == 0 ||
	    strncmp(environ[j], "SHELL=", 6) == 0 ||
	    strncmp(environ[j], "TERM=", 5) == 0 ||
	    strncmp(environ[j], "DISPLAY=", 8) == 0 ||
	    strncmp(environ[j], "PRINTER=", 8) == 0 ||
	    strncmp(environ[j], "XAUTHORITY=", 11) == 0 ||
	    strncmp(environ[j], "TERMCAP=", 8) == 0)
	  env[i++] = environ[j];
      env[i] = NULL;

      execve("/bin/sh", args, env);
      fatal("execv /bin/sh failed: %s", strerror(errno));
    }

  /* Parent. */
  if (type[0] == 'r')
    { /* It is for reading. */
      close(fds[1]);
      return fds[0];
    }
  else
    { /* It is for writing. */
      close(fds[0]);
      return fds[1];
    }
}

/* This function is the main loop of the child.  This never returns. */

static void userfile_child_server()
{
  int type, handle, ret, ret2;
  unsigned int max_bytes, flags, len, whence;
  mode_t mode;
  off_t offset;
  char *path, *cp, *command;
  char buf[8192];
  struct stat st;

  for (;;)
    {
      type = userfile_read_raw();
      switch (type)
	{
	case USERFILE_OPEN:
	  path = buffer_get_string(&packet, NULL);
	  flags = buffer_get_int(&packet);
	  mode = buffer_get_int(&packet);

	  ret = open(path, flags, mode);

	  userfile_packet_start(USERFILE_OPEN_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  xfree(path);
	  break;

	case USERFILE_READ:
	  handle = buffer_get_int(&packet);
	  max_bytes = buffer_get_int(&packet);

	  if (max_bytes >= sizeof(buf))
	    max_bytes = sizeof(buf);
	  ret = read(handle, buf, max_bytes);
	  if (ret < 0)
	    ret = 0;

	  userfile_packet_start(USERFILE_READ_REPLY);
	  buffer_put_string(&packet, buf, ret);
	  userfile_packet_send();

	  break;
	  
	case USERFILE_WRITE:
	  handle = buffer_get_int(&packet);
	  cp = buffer_get_string(&packet, &len);

	  ret = write(handle, cp, len);

	  userfile_packet_start(USERFILE_WRITE_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  xfree(cp);
	  break;

	case USERFILE_CLOSE:
	  handle = buffer_get_int(&packet);

	  ret = close(handle);

	  userfile_packet_start(USERFILE_CLOSE_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  break;

	case USERFILE_LSEEK:
	  handle = buffer_get_int(&packet);
	  offset = buffer_get_int(&packet);
	  whence = buffer_get_int(&packet);

	  ret = lseek(handle, offset, whence);

	  userfile_packet_start(USERFILE_LSEEK_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  break;

	case USERFILE_MKDIR:
	  path = buffer_get_string(&packet, NULL);
	  mode = buffer_get_int(&packet);

	  ret = mkdir(path, mode);

	  userfile_packet_start(USERFILE_MKDIR_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  xfree(path);
	  break;

	case USERFILE_STAT:
	  path = buffer_get_string(&packet, NULL);

	  ret = stat(path, &st);

	  userfile_packet_start(USERFILE_STAT_REPLY);
	  buffer_put_int(&packet, ret);
	  buffer_append(&packet, (void *)&st, sizeof(st));
	  userfile_packet_send();

	  xfree(path);
	  break;
	  
	case USERFILE_REMOVE:
	  path = buffer_get_string(&packet, NULL);

	  ret = remove(path);

	  userfile_packet_start(USERFILE_REMOVE_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  xfree(path);
	  break;

	case USERFILE_POPEN:
	  command = buffer_get_string(&packet, NULL);
	  cp = buffer_get_string(&packet, NULL);

	  ret = do_popen(command, cp);

	  userfile_packet_start(USERFILE_POPEN_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  xfree(command);
	  xfree(cp);
	  break;

	case USERFILE_PCLOSE:
	  handle = buffer_get_int(&packet);

	  ret = close(handle);
	  ret2 = wait(NULL);
	  if (ret >= 0)
	    ret = ret2;

	  userfile_packet_start(USERFILE_PCLOSE_REPLY);
	  buffer_put_int(&packet, ret);
	  userfile_packet_send();

	  break;

	case USERFILE_GET_DES_1_MAGIC_PHRASE:
	  {
	    char *buf = NULL;
#ifdef SECURE_RPC
	    buf = userfile_get_des_1_magic_phrase(geteuid());
#endif
	    userfile_packet_start(USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY);
	    if (buf == NULL)
	      buffer_put_string(&packet, "", 0);
	    else
	      {
		buffer_put_string(&packet, buf, strlen(buf));
		memset(buf, 0, strlen(buf));
	      }
	    userfile_packet_send();
	  }
	  break;

	default:
	  fatal("userfile_child_server: packet type %d", type);
	}
    }
}

/* Initializes reading as a user.  Before calling this, I/O may only be
   performed as the user that is running the current program (current
   effective uid).  SIGPIPE should be set to ignored before this call.
   The cleanup callback will be called in the child before switching to the
   user's uid.  The callback may be NULL. */

void userfile_init(const char *username, uid_t uid, gid_t gid,
		   void (*cleanup_callback)(void *), void *context)
{
  int fds[2], pid;

  if (userfile_initialized)
    fatal("userfile_init already called");
  
  userfile_uid = uid;
  userfile_initialized = 1;

  if (pipe(fds) < 0)
    fatal("pipe: %s", strerror(errno));
  userfile_tochild = fds[1];
  userfile_fromparent = fds[0];
  
  if (pipe(fds) < 0)
    fatal("pipe: %s", strerror(errno));
  userfile_fromchild = fds[0];
  userfile_toparent = fds[1];
  
  pid = fork();
  if (pid < 0)
    fatal("fork: %s", strerror(errno));

  if (pid != 0)
    { 
      /* Parent. */
      userfile_input = userfile_fromchild;
      userfile_output = userfile_tochild;
      close(userfile_toparent);
      close(userfile_fromparent);
      return;
    }

  /* Child. */
  userfile_input = userfile_fromparent;
  userfile_output = userfile_toparent;
  close(userfile_tochild);
  close(userfile_fromchild);

  /* Call the cleanup callback if given. */
  if (cleanup_callback)
    (*cleanup_callback)(context);
  
  /* Reset signals to their default settings. */
  signals_reset();

  /* Child.  We will start serving request. */
  if (uid != geteuid() || uid != getuid())
    {
      if (setgid(gid) < 0)
	fatal("setgid: %s", strerror(errno));

#ifdef HAVE_INITGROUPS
      if (initgroups(username, gid) < 0)
	fatal("initgroups: %s", strerror(errno));
#endif /* HAVE_INITGROUPS */

      if (setuid(uid) < 0)
	fatal("setuid: %s", strerror(errno));
    }

  /* Enter the server main loop. */
  userfile_child_server();
}

/* Closes any open pipes held by userfile.  This should be called
   after a fork while the userfile is open. */

void userfile_close_pipes()
{
  if (!userfile_initialized)
    return;
  userfile_initialized = 0;
  close(userfile_fromchild);
  close(userfile_tochild);
}

/* Stops reading files as an ordinary user.  It is not an error to call
   this even if the system is not initialized. */

void userfile_uninit()
{
  int status;

  if (!userfile_initialized)
    return;
  
  userfile_close_pipes();

  wait(&status);
}

/* Data structure for UserFiles. */

struct UserFile
{
  enum { USERFILE_LOCAL, USERFILE_REMOTE } type;
  int handle; /* Local: file handle; remote: index to descriptor array. */
  unsigned char buf[512];
  unsigned int buf_first;
  unsigned int buf_last;
};

/* Allocates a UserFile handle and initializes it. */

static UserFile userfile_make_handle(int type, int handle)
{
  UserFile uf;

  uf = xmalloc(sizeof(*uf));
  uf->type = type;
  uf->handle = handle;
  uf->buf_first = 0;
  uf->buf_last = 0;
  return uf;
}

/* Encapsulate a normal file descriptor inside a struct UserFile */
UserFile userfile_encapsulate_fd(int fd)
{
  return userfile_make_handle(USERFILE_LOCAL, fd);
}

/* Opens a file using the given uid.  The uid must be either the current
   effective uid (in which case userfile_init need not have been called) or
   the uid passed to a previous call to userfile_init.  Returns a pointer
   to a structure, or NULL if an error occurred.  The flags and mode arguments
   are identical to open(). */

UserFile userfile_open(uid_t uid, const char *path, int flags, mode_t mode)
{
  int handle;

  if (uid == geteuid())
    {
      handle = open(path, flags, mode);
      if (handle < 0)
	return NULL;
      return userfile_make_handle(USERFILE_LOCAL, handle);
    }

  if (!userfile_initialized)
    fatal("userfile_open: using non-current uid but not initialized (uid=%d, path=%.50s)",
	  (int)uid, path);
  
  if (uid != userfile_uid)
    fatal("userfile_open: uid not current and not that of child: uid=%d, path=%.50s",
	  (int)uid, path);

  userfile_packet_start(USERFILE_OPEN);
  buffer_put_string(&packet, path, strlen(path));
  buffer_put_int(&packet, flags);
  buffer_put_int(&packet, mode);
  userfile_packet_send();

  userfile_packet_read(USERFILE_OPEN_REPLY);
  handle = buffer_get_int(&packet);
  if (handle < 0)
    return NULL;

  return userfile_make_handle(USERFILE_REMOTE, handle);
}

/* Closes the userfile handle.  Returns >= 0 on success, and < 0 on error. */

int userfile_close(UserFile uf)
{
  int ret;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = close(uf->handle);
      xfree(uf);
      return ret;

    case USERFILE_REMOTE:
      userfile_packet_start(USERFILE_CLOSE);
      buffer_put_int(&packet, uf->handle);
      userfile_packet_send();
      
      userfile_packet_read(USERFILE_CLOSE_REPLY);
      ret = buffer_get_int(&packet);

      xfree(uf);
      return ret;

    default:
      fatal("userfile_close: type %d", uf->type);
      /*NOTREACHED*/
      return -1;
    }
}

/* Get more data from the child into the buffer.  Returns false if no more
   data is available (EOF). */

static int userfile_fill(UserFile uf)
{
  unsigned int len;
  char *cp;
  int ret;

  if (uf->buf_first < uf->buf_last)
    fatal("userfile_fill: buffer not empty");

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = read(uf->handle, uf->buf, sizeof(uf->buf));
      if (ret <= 0)
	return 0;
      uf->buf_first = 0;
      uf->buf_last = ret;
      break;

    case USERFILE_REMOTE:
      userfile_packet_start(USERFILE_READ);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, sizeof(uf->buf));
      userfile_packet_send();

      userfile_packet_read(USERFILE_READ_REPLY);
      cp = buffer_get_string(&packet, &len);
      if (len > sizeof(uf->buf))
	fatal("userfile_fill: got more than data than requested");
      memcpy(uf->buf, cp, len);
      xfree(cp);
      if (len == 0)
	return 0;
      uf->buf_first = 0;
      uf->buf_last = len;
      break;

    default:
      fatal("userfile_fill: type %d", uf->type);
    }

  return 1;
}

/* Returns the next character from the file (as an unsigned integer) or -1
   if an error is encountered. */

int userfile_getc(UserFile uf)
{
  if (uf->buf_first >= uf->buf_last)
    {
      if (!userfile_fill(uf))
	return -1;
      
      if (uf->buf_first >= uf->buf_last)
	fatal("userfile_getc/fill error");
    }
  
  return uf->buf[uf->buf_first++];
}

/* Reads data from the file.  Returns as much data as is the buffer
   size, unless end of file is encountered.  Returns the number of bytes
   read, 0 on EOF, and -1 on error. */

int userfile_read(UserFile uf, void *buf, unsigned int len)
{
  unsigned int i;
  int ch;
  unsigned char *ucp;
  
  ucp = buf;
  for (i = 0; i < len; i++)
    {
      ch = userfile_getc(uf);
      if (ch == -1)
	break;
      ucp[i] = ch;
    }
  
  return i;
}

/* Writes data to the file.  Writes all data, unless an error is encountered.
   Returns the number of bytes actually written; -1 indicates error. */

int userfile_write(UserFile uf, const void *buf, unsigned int len)
{
  unsigned int chunk_len, offset;
  int ret;
  const unsigned char *ucp;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return write(uf->handle, buf, len);
      
    case USERFILE_REMOTE:
      ucp = buf;
      for (offset = 0; offset < len; )
	{
	  chunk_len = len - offset;
	  if (chunk_len > 16000)
	    chunk_len = 16000;
	  
	  userfile_packet_start(USERFILE_WRITE);
	  buffer_put_int(&packet, uf->handle);
	  buffer_put_string(&packet, ucp + offset, chunk_len);
	  userfile_packet_send();
	  
	  userfile_packet_read(USERFILE_WRITE_REPLY);
	  ret = buffer_get_int(&packet);
	  if (ret < 0)
	    return -1;
	  offset += ret;
	  if (ret != chunk_len)
	    break;
	}
      return offset;

    default:
      fatal("userfile_write: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

/* Reads a line from the file.  The line will be null-terminated, and
   will include the newline.  Returns a pointer to the given buffer,
   or NULL if no more data was available.  If a line is too long,
   reads as much as the buffer can accommodate (and null-terminates
   it).  If the last line of the file does not terminate with a
   newline, returns the line, null-terminated, but without a
   newline. */

char *userfile_gets(char *buf, unsigned int size, UserFile uf)
{
  unsigned int i;
  int ch;

  for (i = 0; i < size - 1; )
    {
      ch = userfile_getc(uf);
      if (ch == -1)
	break;
      buf[i++] = ch;
      if (ch == '\n')
	break;
    }
  if (i == 0)
    return NULL;

  buf[i] = '\0';
  
  return buf;
}

/* Performs lseek() on the given file. */

off_t userfile_lseek(UserFile uf, off_t offset, int whence)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return lseek(uf->handle, offset, whence);
      
    case USERFILE_REMOTE:
      userfile_packet_start(USERFILE_LSEEK);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, offset);
      buffer_put_int(&packet, whence);
      userfile_packet_send();

      userfile_packet_read(USERFILE_LSEEK_REPLY);
      return buffer_get_int(&packet);

    default:
      fatal("userfile_lseek: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

/* Creates a directory using the given uid. */

int userfile_mkdir(uid_t uid, const char *path, mode_t mode)
{
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return mkdir(path, mode);

  if (!userfile_initialized)
    fatal("userfile_mkdir with uid %d", (int)uid);
  
  if (uid != userfile_uid)
    fatal("userfile_mkdir with wrong uid %d", (int)uid);

  userfile_packet_start(USERFILE_MKDIR);
  buffer_put_string(&packet, path, strlen(path));
  buffer_put_int(&packet, mode);
  userfile_packet_send();

  userfile_packet_read(USERFILE_MKDIR_REPLY);
  return buffer_get_int(&packet);
}

/* Performs stat() using the given uid. */

int userfile_stat(uid_t uid, const char *path, struct stat *st)
{
  int ret;

  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return stat(path, st);

  if (!userfile_initialized)
    fatal("userfile_stat with uid %d", (int)uid);
  
  if (uid != userfile_uid)
    fatal("userfile_stat with wrong uid %d", (int)uid);

  userfile_packet_start(USERFILE_STAT);
  buffer_put_string(&packet, path, strlen(path));
  userfile_packet_send();

  userfile_packet_read(USERFILE_STAT_REPLY);
  ret = buffer_get_int(&packet);
  buffer_get(&packet, (char *)st, sizeof(*st));

  return ret;
}

/* Performs remove() using the given uid. */

int userfile_remove(uid_t uid, const char *path)
{
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return remove(path);

  if (!userfile_initialized)
    fatal("userfile_remove with uid %d", (int)uid);
  
  if (uid != userfile_uid)
    fatal("userfile_remove with wrong uid %d", (int)uid);

  userfile_packet_start(USERFILE_REMOVE);
  buffer_put_string(&packet, path, strlen(path));
  userfile_packet_send();

  userfile_packet_read(USERFILE_REMOVE_REPLY);
  return buffer_get_int(&packet);
}

/* Performs popen() on the given uid; returns a file from where the output
   of the command can be read (type == "r") or to where data can be written
   (type == "w"). */

UserFile userfile_popen(uid_t uid, const char *command, const char *type)
{
  int handle;

  if (uid == geteuid())
    {
      handle = do_popen(command, type);
      if (handle < 0)
	return NULL;
      return userfile_make_handle(USERFILE_LOCAL, handle);
    }

  if (!userfile_initialized)
    fatal("userfile_popen: using non-current uid but not initialized (uid=%d)",
	  (int)uid);
  
  if (uid != userfile_uid)
    fatal("userfile_popen: uid not current and not that of child: uid=%d",
	  (int)uid);

  userfile_packet_start(USERFILE_POPEN);
  buffer_put_string(&packet, command, strlen(command));
  buffer_put_string(&packet, type, strlen(type));
  userfile_packet_send();

  userfile_packet_read(USERFILE_POPEN_REPLY);
  handle = buffer_get_int(&packet);
  if (handle < 0)
    return NULL;

  return userfile_make_handle(USERFILE_REMOTE, handle);
}

/* Performs pclose() on the given uid.  Returns <0 if an error occurs. */

int userfile_pclose(UserFile uf)
{
  int ret, ret2;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = close(uf->handle);
      ret2 = wait(NULL);
      if (ret >= 0)
	ret = ret2;
      xfree(uf);
      return ret;

    case USERFILE_REMOTE:
      userfile_packet_start(USERFILE_PCLOSE);
      buffer_put_int(&packet, uf->handle);
      userfile_packet_send();
      
      userfile_packet_read(USERFILE_PCLOSE_REPLY);
      ret = buffer_get_int(&packet);

      xfree(uf);
      return ret;

    default:
      fatal("userfile_close: type %d", uf->type);
      /*NOTREACHED*/
      return -1;
    }
}

/* Get sun des 1 magic phrase */
char *userfile_get_des_1_magic_phrase(uid_t uid)
{
  char *phrase = NULL;
#ifndef SECURE_RPC
  return phrase;
#else
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    {
      char buf[MAXNETNAMELEN + 1];
      des_block block;
      
      memset(buf, 0, sizeof(buf));
      sprintf(buf, "ssh.%04X", geteuid());
      memcpy(block.c, buf, sizeof(block.c));
      if (getnetname(buf))
	{
	  if (key_encryptsession(buf, &block) == 0)
	    {
	      sprintf(buf, "%08X%08X", ntohl(block.key.high),
		      ntohl(block.key.low));
	      memset(block.c, 0, sizeof(block.c));
	      phrase = xstrdup(buf);
	      memset(buf, 0, sizeof(buf));
	    }
	}
      return phrase;
    }
  
  if (!userfile_initialized)
    fatal("userfile_get_des_1_magic_phrase with uid %d", (int)uid);
  
  if (uid != userfile_uid)
    fatal("userfile_get_des_1_magic_phrase with wrong uid %d", (int)uid);

  userfile_packet_start(USERFILE_GET_DES_1_MAGIC_PHRASE);
  userfile_packet_send();

  userfile_packet_read(USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY);
  phrase =  buffer_get_string(&packet, NULL);
  if (strlen(phrase) == 0)
    {
      xfree(phrase);
      return NULL;
    }
  return phrase;
#endif
}


int userfile_check_owner_permissions(struct passwd *pw, const char *path)
{
  struct stat st;
  if (userfile_stat(pw->pw_uid, path, &st) < 0)
    return 0;

  if ((st.st_uid != UID_ROOT && st.st_uid != pw->pw_uid) ||
#ifdef ALLOW_GROUP_WRITEABILITY
      (st.st_mode & 002) != 0
#else
      (st.st_mode & 022) != 0
#endif
      )
    return 0;
  else
    return 1;
}

