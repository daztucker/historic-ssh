/*

login.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 24 14:51:08 1995 ylo
Last modified: Wed Jul 12 02:23:49 1995 ylo

This file performs some of the things login(1) normally does.  We cannot
easily use something like login -p -h host -f user, because there are
several different logins around, and it is hard to determined what kind of
login the current system has.  Also, we want to be able to execute commands
on a tty.

*/

#include "includes.h"
#ifdef HAVE_UTMP_H
#include <utmp.h>
#ifdef HAVE_LASTLOG_H
#include <lastlog.h> /* Some have the definitions in utmp.h. */
#endif /* HAVE_LASTLOG_H */
#endif /* HAVE_UTMP_H */
#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif /* HAVE_UTMPX_H */
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */
#include "ssh.h"

/* Returns the time when the user last logged in.  Returns 0 if the 
   information is not available.  This must be called before record_login. */

#ifdef LASTLOG_IS_DIR
unsigned long get_last_login_time(uid_t uid, const char *name, 
				  char *buf, unsigned int bufsize)
{
#ifdef HAVE_LASTLOG_H
  struct lastlog ll;
  char lastlogfile[100];
  int fd;

#ifdef _PATH_LASTLOG
  sprintf(lastlogfile, "%s/%s", _PATH_LASTLOG, name);
#else
#ifdef LASTLOG_FILE
  sprintf(lastlogfile, "%s/%s", LASTLOG_FILE, name);
#else
  sprintf(lastlogfile, "/var/adm/lastlog/%s", name);
#endif
#endif

  strcpy(buf, "");

  fd = open(lastlogfile, O_RDONLY);
  if (fd < 0)
    return 0;
  if (read(fd, &ll, sizeof(ll)) != sizeof(ll))
    {
      close(fd);
      return 0;
    }
  close(fd);
  if (bufsize > sizeof(ll.ll_host) + 1)
    bufsize = sizeof(ll.ll_host) + 1;
  strncpy(buf, ll.ll_host, bufsize - 1);
  buf[bufsize - 1] = 0;
  return ll.ll_time;
  
#else /* HAVE_LASTLOG_H */

  return 0;

#endif /* HAVE_LASTLOG_H */
}

#else /* LASTLOG_IS_DIR */

unsigned long get_last_login_time(uid_t uid, const char *logname,
				  char *buf, unsigned int bufsize)
{
#ifdef HAVE_LASTLOG_H

  struct lastlog ll;
  char *lastlog;
  int fd;

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = "/var/adm/lastlog";
#endif
#endif

  strcpy(buf, "");

  fd = open(lastlog, O_RDONLY);
  if (fd < 0)
    return 0;
  lseek(fd, (off_t)((long)uid * sizeof(ll)), 0);
  if (read(fd, &ll, sizeof(ll)) != sizeof(ll))
    {
      close(fd);
      return 0;
    }
  close(fd);
  if (bufsize > sizeof(ll.ll_host) + 1)
    bufsize = sizeof(ll.ll_host) + 1;
  strncpy(buf, ll.ll_host, bufsize - 1);
  buf[bufsize - 1] = 0;
  return ll.ll_time;

#else /* HAVE_LASTLOG_H */

#ifdef HAVE_USERSEC_H

  char *lasthost;
  int lasttime;
  if (setuserdb(S_READ) < 0)
    return 0;
  if (getuserattr((char *)logname, S_LASTTIME, &lasttime, SEC_INT) < 0)
    {
      enduserdb();
      return 0;
    }
  if (getuserattr((char *)logname, S_LASTHOST, &lasthost, SEC_CHAR) < 0)
    {
      enduserdb();
      return 0;
    }
  strncpy(buf, lasthost, bufsize);
  buf[bufsize - 1] = 0;
  if (enduserdb() < 0)
    return 0;
  return lasttime;

#else /* HAVE_USERSEC_H */
  
  return 0;

#endif /* HAVE_USERSEC_H */

#endif /* HAVE_LASTLOG_H */
}
#endif /* LASTLOG_IS_DIR */

/* Records that the user has logged in.  I these parts of operating systems
   were more standardized. */

void record_login(int pid, const char *ttyname, const char *user, uid_t uid,
		  const char *host)
{
  int fd;

#ifdef HAVE_LASTLOG_H
  struct lastlog ll;
  char *lastlog;
#ifdef LASTLOG_IS_DIR
  char lastlogfile[100];
#endif /* LASTLOG_IS_DIR */
#endif /* HAVE_LASTLOG_H */

#if defined(HAVE_UTMP_H) && !defined(HAVE_UTMPX_H)
  struct utmp u, u2;
  off_t offset;
  const char *utmp, *wtmp;

  /* Construct an utmp/wtmp entry. */
  memset(&u, 0, sizeof(u));
#ifdef LOGIN_PROCESS
  if (strcmp(user, "") == 0)
    u.ut_type = DEAD_PROCESS; /* logout */
  else
    u.ut_type = USER_PROCESS;
#endif /* LOGIN_PROCESS */
#ifdef HAVE_PID_IN_UTMP
  u.ut_pid = pid;
#endif /* PID_IN_UTMP */
#ifdef HAVE_ID_IN_UTMP
#ifdef __sgi
    strncpy(u.ut_id, ttyname + 8, sizeof(u.ut_id)); /* /dev/ttyq99 -> q99 */
#else /* __sgi */
    if (sizeof(u.ut_id) > 4)
      strncpy(u.ut_id, ttyname + 5, sizeof(u.ut_id));
    else
      strncpy(u.ut_id, ttyname + strlen(ttyname) - 2, sizeof(u.ut_id));
#endif /* __sgi */
#endif /* HAVE_ID_IN_UTMP */
  strncpy(u.ut_line, ttyname + 5, sizeof(u.ut_line));
  u.ut_time = time(NULL);
#ifdef HAVE_NAME_IN_UTMP
  strncpy(u.ut_name, user, sizeof(u.ut_name));
#else /* HAVE_NAME_IN_UTMP */
  strncpy(u.ut_user, user, sizeof(u.ut_user));
#endif /* HAVE_NAME_IN_UTMP */
#ifdef HAVE_HOST_IN_UTMP
  strncpy(u.ut_host, host, sizeof(u.ut_host));
#endif /* HAVE_HOST_IN_UTMP */

  /* Figure out the file names. */
#ifdef _PATH_UTMP
  utmp = _PATH_UTMP;
  wtmp = _PATH_WTMP;
#else
#ifdef UTMP_FILE
  utmp = UTMP_FILE;
  wtmp = WTMP_FILE;
#else
  utmp = "/var/adm/utmp";
  wtmp = "/var/adm/wtmp";
#endif
#endif
  
  /* Append an entry to wtmp. */
  fd = open(wtmp, O_WRONLY|O_APPEND);
  if (fd >= 0)
    {
      if (write(fd, &u, sizeof(u)) != sizeof(u))
	log("Could not write %s: %s", wtmp, strerror(errno));
      close(fd);
    }

  /* Replace the proper entry in utmp, as identified by ut_line.  Append a
     new entry if the line could not be found. */
  fd = open(utmp, O_RDWR);
  if (fd >= 0)
    {
      while (1)
	{
	  offset = lseek(fd, (off_t)0L, 1);
	  if (read(fd, &u2, sizeof(u2)) != sizeof(u2))
	    {
	      lseek(fd, offset, 0);
	      if (write(fd, &u, sizeof(u)) != sizeof(u))
		log("Could not append %s: %s", utmp, strerror(errno));
	      break;
	    }
	  if (strncmp(u2.ut_line, ttyname + 5, sizeof(u2.ut_line)) == 0)
	    {
	      lseek(fd, offset, 0);
	      if (write(fd, &u, sizeof(u)) != sizeof(u))
		log("Could not write %s: %s", utmp, strerror(errno));
	      break;
	    }
	}
      close(fd);
    }
#endif /* HAVE_UTMP_H && !HAVE_UTMPX_H */

#ifdef HAVE_UTMPX_H
  {
    struct utmpx ux, *uxp;
    memset(&ux, 0, sizeof(ux));
    strncpy(ux.ut_line, ttyname + 5, sizeof(ux.ut_line));
    uxp = getutxline(&ux);
    if (uxp)
      ux = *uxp;
    strncpy(ux.ut_user, user, sizeof(ux.ut_user));
#ifdef __sgi
    strncpy(ux.ut_id, ttyname + 8, sizeof(ux.ut_id)); /* /dev/ttyq99 -> q99 */
#else /* __sgi */
    if (sizeof(ux.ut_id) > 4)
      strncpy(ux.ut_id, ttyname + 5, sizeof(ux.ut_id));
    else
      strncpy(ux.ut_id, ttyname + strlen(ttyname) - 2, sizeof(ux.ut_id));
#endif /* __sgi */
    ux.ut_pid = pid;
    if (strcmp(user, "") == 0)
      ux.ut_type = DEAD_PROCESS;
    else
      ux.ut_type = USER_PROCESS;
    gettimeofday(&ux.ut_tv);
    ux.ut_session = pid;
    strncpy(ux.ut_host, host, sizeof(ux.ut_host));
    ux.ut_host[sizeof(ux.ut_host) - 1] = 0;
    ux.ut_syslen = strlen(ux.ut_host);
    pututxline(&ux);
    updwtmpx(WTMPX_FILE, &ux);
    endutxent();
  }
#endif /* HAVE_UTMPX_H */

#ifdef HAVE_LASTLOG_H

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = "/var/adm/lastlog";
#endif
#endif

#ifdef LASTLOG_IS_DIR
  sprintf(lastlogfile, "%s/%s", lastlog, user);
#endif

  /* Update lastlog unless actually recording a logout. */
  if (strcmp(user, "") != 0)
    {
      /* It is safer to bzero the lastlog structure first because some
	 systems might have some extra fields in it (e.g. SGI) */
      memset(&ll, 0, sizeof(ll));

      /* Update lastlog. */
      ll.ll_time = time(NULL);
      strncpy(ll.ll_line, ttyname + 5, sizeof(ll.ll_line));
      strncpy(ll.ll_host, host, sizeof(ll.ll_host));
#ifdef LASTLOG_IS_DIR
      fd = open(lastlogfile, O_WRONLY | O_CREAT, 0644);
      if (fd >= 0)
	{
	  if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
	    log("Could not write %s: %s", lastlogfile, strerror(errno));
	  close(fd);
	} 
      else 
	{
	  log("Could not open %s: %s", lastlogfile, strerror(errno));
	}
#else /* LASTLOG_IS_DIR */
      fd = open(lastlog, O_RDWR);
      if (fd >= 0)
	{
	  lseek(fd, (off_t)((long)uid * sizeof(ll)), 0);
	  if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
	    log("Could not write %s: %s", lastlog, strerror(errno));
	  close(fd);
	}
#endif /* LASTLOG_IS_DIR */
    }
#endif /* HAVE_LASTLOG_H */

#ifdef HAVE_USERSEC_H

  if (strcmp(user, "") != 0)
    {
      int lasttime = time(NULL);
      if (setuserdb(S_WRITE) < 0)
	log("setuserdb S_WRITE failed: %s", strerror(errno));
      if (putuserattr((char *)user, S_LASTTIME, (void *)lasttime, SEC_INT) < 0)
	log("putuserattr S_LASTTIME failed: %s", strerror(errno));
      if (putuserattr((char *)user, S_LASTTTY, (void *)(ttyname + 5), 
		      SEC_CHAR) < 0)
	log("putuserattr S_LASTTTY %.900s failed: %s", 
	    ttyname, strerror(errno));
      if (putuserattr((char *)user, S_LASTHOST, (void *)host, SEC_CHAR) < 0)
	log("putuserattr S_LASTHOST %.900s failed: %s", host, strerror(errno));
      if (putuserattr((char *)user, 0, NULL, SEC_COMMIT) < 0)
	log("putuserattr SEC_COMMIT failed: %s", strerror(errno));
      if (enduserdb() < 0)
	log("enduserdb failed: %s", strerror(errno));
    }
#endif   
}
  
/* Records that the user has logged out. */

void record_logout(int pid, const char *ttyname, const char *host)
{
  record_login(pid, ttyname, "", -1, host);
}