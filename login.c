/*

login.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 24 14:51:08 1995 ylo

This file performs some of the things login(1) normally does.  We cannot
easily use something like login -p -h host -f user, because there are
several different logins around, and it is hard to determined what kind of
login the current system has.  Also, we want to be able to execute commands
on a tty.

*/

/*
 * $Id: login.c,v 1.9 1998/04/30 01:52:43 kivinen Exp $
 * $Log: login.c,v $
 * Revision 1.9  1998/04/30 01:52:43  kivinen
 * 	Moved copying of user name to utmp structure to be done only
 * 	in login.
 *
 * Revision 1.8  1998/04/17 00:38:38  kivinen
 * 	Fixed ttyslot code.
 *
 * Revision 1.7  1997/03/26 07:09:49  kivinen
 * 	Added HAVE_NO_TZ_IN_GETTIMEOFDAY support.
 *
 * Revision 1.6  1997/01/10 16:15:19  ttsalo
 *     Merged ttyslot patch for SunOS/Solaris from Scott Schwartz
 *
 * Revision 1.5  1996/10/29 22:38:58  kivinen
 * 	log -> log_msg.
 *
 * Revision 1.4  1996/07/12 07:20:49  ttsalo
 * 	utmp fix for cray (handled like sgi)
 *
 * Revision 1.3  1996/06/27 12:44:08  ttsalo
 *         FreeBSD with long hostnames in utmp fixed (again).
 *
 * Revision 1.2  1996/06/27 12:30:32  ttsalo
 * 	FreeBSD with long hostnames in utmp fixed.
 * 	Also small changes for SCO.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.7  1995/09/21  17:11:52  ylo
 * 	Added NULL second argument to gettimeofday.
 *
 * Revision 1.6  1995/09/09  21:26:43  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.5  1995/07/27  00:38:43  ylo
 * 	Use SSH_{WTMP,UTMP,LASTLOG} instead of hard-coded default
 * 	values if path not defined in header.
 *
 * Revision 1.4  1995/07/16  01:03:11  ylo
 * 	Clear host name field in record_logout.
 * 	Test DEAD_PROCESS instead of LOGIN_PROCESS in ifdef.
 *
 * Revision 1.3  1995/07/15  13:25:17  ylo
 * 	NEXTSTEP patches from Ray Spalding.
 *
 * Revision 1.2  1995/07/13  01:26:29  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
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
#ifndef SCO
#include <sys/mkdev.h>	/* for minor() */
#endif
#endif /* HAVE_UTMPX_H */
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */
#include "ssh.h"

/* Returns the time when the user last logged in.  Returns 0 if the 
   information is not available.  This must be called before record_login. 
   The host the user logged in from will be returned in buf. */

#ifdef LASTLOG_IS_DIR
unsigned long get_last_login_time(uid_t uid, const char *name, 
				  char *buf, unsigned int bufsize)
{
#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)
  struct lastlog ll;
  char lastlogfile[500];
  int fd;

#ifdef _PATH_LASTLOG
  sprintf(lastlogfile, "%.200s/%.200s", _PATH_LASTLOG, name);
#else
#ifdef LASTLOG_FILE
  sprintf(lastlogfile, "%.200s/%.200s", LASTLOG_FILE, name);
#else
  sprintf(lastlogfile, "%.200s/%.200s", SSH_LASTLOG, name);
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
  
#else /* HAVE_LASTLOG_H || HAVE_LASTLOG */

  return 0;

#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */
}

#else /* LASTLOG_IS_DIR */

/* Returns the time when the user last logged in (or 0 if no previous login
   is found).  The name of the host used last time is returned in buf. */

unsigned long get_last_login_time(uid_t uid, const char *logname,
				  char *buf, unsigned int bufsize)
{
#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)

  struct lastlog ll;
  char *lastlog;
  int fd;

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = SSH_LASTLOG;
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

#else /* HAVE_LASTLOG_H || HAVE_LASTLOG */

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

#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */
}
#endif /* LASTLOG_IS_DIR */

/* Records that the user has logged in.  I these parts of operating systems
   were more standardized. */

void record_login(int pid, const char *ttyname, const char *user, uid_t uid,
		  const char *host, struct sockaddr_in *addr)
{
  int fd;

#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)
  struct lastlog ll;
  char *lastlog;
#ifdef LASTLOG_IS_DIR
  char lastlogfile[100];
#endif /* LASTLOG_IS_DIR */
#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */

#if defined(HAVE_UTMP_H) && !defined(HAVE_UTMPX_H)
  struct utmp u, u2;
  off_t offset;
  const char *utmp, *wtmp;

  /* Construct an utmp/wtmp entry. */
  memset(&u, 0, sizeof(u));
#ifdef DEAD_PROCESS
  if (strcmp(user, "") == 0)
    u.ut_type = DEAD_PROCESS; /* logout */
  else
    u.ut_type = USER_PROCESS;
#endif /* LOGIN_PROCESS */
#ifdef HAVE_PID_IN_UTMP
  u.ut_pid = pid;
#endif /* PID_IN_UTMP */
#ifdef HAVE_ID_IN_UTMP
#if defined(__sgi) || defined(CRAY)
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
#ifdef __FreeBSD__
  if (strlen(host) > sizeof(u.ut_host)) {
    strncpy(u.ut_host, get_remote_ipaddr(), sizeof(u.ut_host));
  }
#endif /* __FreeBSD__ */
#endif /* HAVE_HOST_IN_UTMP */
#ifdef HAVE_ADDR_IN_UTMP
  if (addr)
    memcpy(&u.ut_addr, &addr->sin_addr, sizeof(u.ut_addr));
  else
    memset(&u.ut_addr, 0, sizeof(u.ut_addr));
#endif

  /* Figure out the file names. */
#ifdef _PATH_UTMP
  utmp = _PATH_UTMP;
  wtmp = _PATH_WTMP;
#else
#ifdef UTMP_FILE
  utmp = UTMP_FILE;
  wtmp = WTMP_FILE;
#else
  utmp = SSH_UTMP;
  wtmp = SSH_WTMP;
#endif
#endif
  
#ifdef HAVE_LIBUTIL_LOGIN
  login(&u);
#else /* HAVE_LIBUTIL_LOGIN */
  /* Append an entry to wtmp. */
  fd = open(wtmp, O_WRONLY|O_APPEND);
  if (fd >= 0)
    {
      if (write(fd, &u, sizeof(u)) != sizeof(u))
	log_msg("Could not write %.100s: %.100s", wtmp, strerror(errno));
      close(fd);
    }

  /* Replace the proper entry in utmp, as identified by ut_line.  Append a
     new entry if the line could not be found. */
  fd = open(utmp, O_RDWR);
  if (fd >= 0)
    {
#ifdef HAVE_TTYSLOT
      int n = ttyslot();
#if defined(ultrix) || defined(NeXT)
/*
 * the problem is that Berkeley unix uses ttyslot() to determine where in
 * the utmp file to write and it is correct at login time because the
 * controlling tty is correct.  At logout time, I think a different process
 * runs this code and may have a different (or no) controlling tty so
 * we must search for the right record to clobber.  -- corey 5/7/97
 */
      if (n > 0 && *user) {
#else
      if (n > 0) {
#endif
        lseek(fd, (off_t)(n*sizeof(u)), 0);
        if (write(fd, &u, sizeof(u)) != sizeof(u))
	  log_msg("Could not write to %.100s: %.100s", 
	    utmp, strerror(errno));
      } else
#endif
      while (1)
	{
	  offset = lseek(fd, (off_t)0L, 1);
	  if (read(fd, &u2, sizeof(u2)) != sizeof(u2))
	    {
	      lseek(fd, offset, 0);
	      if (write(fd, &u, sizeof(u)) != sizeof(u))
		log_msg("Could not append to %.100s: %.100s", 
		    utmp, strerror(errno));
	      break;
	    }
#if defined(ultrix) || defined(NeXT)            /* corey */
	  if (strcmp(u2.ut_line, ttyname + 5) == 0 && *u2.ut_name)
#else   /* ultrix || NeXT */
	  if (strncmp(u2.ut_line, ttyname + 5, sizeof(u2.ut_line)) == 0)
#endif  /* ultrix || NeXT */
	    {
	      lseek(fd, offset, 0);
	      if (write(fd, &u, sizeof(u)) != sizeof(u))
		log_msg("Could not write to %.100s: %.100s", 
		    utmp, strerror(errno));
	      break;
	    }
	}
      close(fd);
    }
#endif /* HAVE_LIBUTIL_LOGIN */
#endif /* HAVE_UTMP_H && !HAVE_UTMPX_H */

#ifdef HAVE_UTMPX_H
  {
    struct utmpx ux, *uxp;
    memset(&ux, 0, sizeof(ux));
    strncpy(ux.ut_line, ttyname + 5, sizeof(ux.ut_line));
    if (strcmp(user, "") == 0) {
	/* logout; find previous entry for pid and zonk it */
	setutxent();
	while ( (uxp = getutxent()) ) {
		if (uxp->ut_pid != (pid_t)pid)
			continue;
		ux = *uxp;
		break;
	}
	endutxent();
    }
    else {
	/* login: find appropriate slot for this tty */
	uxp = getutxline(&ux);
	if (uxp)
	  ux = *uxp;
	strncpy(ux.ut_user, user, sizeof(ux.ut_user));
    }
#if defined(__sgi) || defined(SCO)
    strncpy(ux.ut_id, ttyname + 8, sizeof(ux.ut_id)); /* /dev/ttyq99 -> q99 */
#else /* __sgi */
    if (sizeof(ux.ut_id) > 4)
      strncpy(ux.ut_id, ttyname + 5, sizeof(ux.ut_id));
    else {
      struct stat st;
      char buf[20];
      
      buf[0] = 0;
      if (stat(ttyname, &st) == 0) {
	/* allow for 1000 /dev/pts devices */
	sprintf(buf, "P%03d", (int)minor(st.st_rdev));
      }
      strncpy(ux.ut_id, buf, sizeof(ux.ut_id));
    }
#endif /* __sgi */
    ux.ut_pid = pid;
    if (strcmp(user, "") == 0)
      ux.ut_type = DEAD_PROCESS;
    else
      ux.ut_type = USER_PROCESS;
#ifdef HAVE_NO_TZ_IN_GETTIMEOFDAY
    gettimeofday(&ux.ut_tv);
#else
    gettimeofday(&ux.ut_tv, NULL);
#endif
    ux.ut_session = pid;
    strncpy(ux.ut_host, host, sizeof(ux.ut_host));
    ux.ut_host[sizeof(ux.ut_host) - 1] = 0;
    ux.ut_syslen = strlen(ux.ut_host);
    ux.ut_exit.e_termination = 0;
    ux.ut_exit.e_exit = 0;
#ifdef HAVE_MAKEUTX
    /*
     * modutx/makeutx notify init(1) to clean up utmpx for this pid
     * automatically if we don't manage to, for some odd reason
     */
    if (strcmp(user, "") == 0)
	modutx(&ux);
    else
	makeutx(&ux);
#else
    pututxline(&ux);
    updwtmpx(WTMPX_FILE, &ux);
#endif
    endutxent();
  }
#endif /* HAVE_UTMPX_H */

#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = SSH_LASTLOG;
#endif
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
      sprintf(lastlogfile, "%.100s/%.100s", lastlog, user);
      fd = open(lastlogfile, O_WRONLY | O_CREAT, 0644);
      if (fd >= 0)
	{
	  if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
	    log_msg("Could not write %.100s: %.100s", 
		lastlogfile, strerror(errno));
	  close(fd);
	} 
      else 
	{
	  log_msg("Could not open %.100s: %.100s", lastlogfile, strerror(errno));
	}
#else /* LASTLOG_IS_DIR */
      fd = open(lastlog, O_RDWR);
      if (fd >= 0)
	{
	  lseek(fd, (off_t)((long)uid * sizeof(ll)), 0);
	  if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
	    log_msg("Could not write %.100s: %.100s", lastlog, strerror(errno));
	  close(fd);
	}
#endif /* LASTLOG_IS_DIR */
    }
#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */

#ifdef HAVE_USERSEC_H

  if (strcmp(user, "") != 0)
    {
      int lasttime = time(NULL);
      if (setuserdb(S_WRITE) < 0)
	log_msg("setuserdb S_WRITE failed: %.100s", strerror(errno));
      if (putuserattr((char *)user, S_LASTTIME, (void *)lasttime, SEC_INT) < 0)
	log_msg("putuserattr S_LASTTIME failed: %.100s", strerror(errno));
      if (putuserattr((char *)user, S_LASTTTY, (void *)(ttyname + 5), 
		      SEC_CHAR) < 0)
	log_msg("putuserattr S_LASTTTY %.900s failed: %.100s", 
	    ttyname, strerror(errno));
      if (putuserattr((char *)user, S_LASTHOST, (void *)host, SEC_CHAR) < 0)
	log_msg("putuserattr S_LASTHOST %.900s failed: %.100s", 
	    host, strerror(errno));
      if (putuserattr((char *)user, 0, NULL, SEC_COMMIT) < 0)
	log_msg("putuserattr SEC_COMMIT failed: %.100s", strerror(errno));
      if (enduserdb() < 0)
	log_msg("enduserdb failed: %.100s", strerror(errno));
    }
#endif   
}
  
/* Records that the user has logged out. */

void record_logout(int pid, const char *ttyname)
{
#ifdef HAVE_LIBUTIL_LOGIN
  const char *line = ttyname + 5; /* /dev/ttyq8 -> ttyq8 */
  if (logout(line))
    logwtmp(line, "", "");
#else /* HAVE_LIBUTIL_LOGIN */
  record_login(pid, ttyname, "", -1, "", NULL);
#endif /* HAVE_LIBUTIL_LOGIN */  
}
