/*

pty.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 17 04:37:25 1995 ylo

Allocating a pseudo-terminal, and making it the controlling tty.

*/

/*
 * $Id: pty.c,v 1.11 1997/03/26 07:09:31 kivinen Exp $
 * $Log: pty.c,v $
 * Revision 1.11  1997/03/26  07:09:31  kivinen
 * 	Changed uid 0 to UID_ROOT.
 *
 * Revision 1.10  1997/03/25 05:39:57  kivinen
 * 	HPUX pty code.
 *
 * Revision 1.9  1996/11/12 15:51:39  ttsalo
 *       FreeBSD pty allocation patch from Andrey Chernov merged.
 *
 * Revision 1.8  1996/10/21 13:28:24  ttsalo
 *       Window resizing fix for ultrix & NeXT from Corey Satten
 *
 * Revision 1.7  1996/09/27 17:19:47  ylo
 * 	Merged ultrix and Next patches from Corey Satten.
 *
 * Revision 1.6  1996/09/05 19:06:09  ttsalo
 * 	Replaced setpgrp() with setpgid(), setpgrp() is not a portable
 * 	function.
 *
 * Revision 1.5  1996/08/11 22:28:55  ylo
 * 	Changed the way controlling tty is set on NeXT.
 *
 * Revision 1.4  1996/07/12 07:26:04  ttsalo
 * 	2 new ways to allocate pty:s: sco-style numbered (/dev/ptyp...)
 * 	ptys and dynix/ptx getpseudotty(). 8 ways in total. (!)
 *
 * Revision 1.3  1996/05/30 22:08:21  ylo
 * 	Don't print errors about I_PUSH ttcompat failing.
 *
 * Revision 1.2  1996/04/26 00:26:06  ylo
 * 	Fixed process group setting on NeXT.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.6  1995/09/21  17:12:07  ylo
 * 	Push ttcompat into streams pty.
 *
 * Revision 1.5  1995/09/13  11:58:18  ylo
 * 	Added Cray support.
 *
 * Revision 1.4  1995/09/09  21:26:44  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.3  1995/07/16  01:03:28  ylo
 * 	Added pty_release.
 *
 * Revision 1.2  1995/07/13  01:28:20  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "pty.h"
#include "ssh.h"

#ifdef __hpux
#include <sys/sysmacros.h>
#endif

/* Pty allocated with _getpty gets broken if we do I_PUSH:es to it. */
#if defined(HAVE__GETPTY) || defined(HAVE_OPENPTY)
#undef HAVE_DEV_PTMX
#endif

#ifdef HAVE_DEV_PTMX
#include <sys/stream.h>
#include <stropts.h>
#include <sys/conf.h>
#endif /* HAVE_DEV_PTMX */

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/* Allocates and opens a pty.  Returns 0 if no pty could be allocated,
   or nonzero if a pty was successfully allocated.  On success, open file
   descriptors for the pty and tty sides and the name of the tty side are 
   returned (the buffer must be able to hold at least 64 characters). */

int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf)
{
#ifdef HAVE_OPENPTY

  /* openpty(3) exists in OSF/1 and some other os'es */

  int i;

  i = openpty(ptyfd, ttyfd, namebuf, NULL, NULL);

  if (i < 0) 
    {
      error("openpty: %.100s", strerror(errno));
      return 0;
    }
  
  return 1;

#else /* HAVE_OPENPTY */
#ifdef HAVE_GETPSEUDOTTY
  
  /* getpseudotty(3SEQ) exists in DYNIX/ptx 2.1 */
  char *slave, *master;
  
  int i;
  
  i = getpseudotty(&slave, &master);
  
  if (i < 0) 
    {
      error("openpty: %.100s", strerror(errno));
      return 0;
    }
  *ptyfd = i;
  strcpy(namebuf, slave);
  *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      error("%.200s: %.100s", namebuf, strerror(errno));
      close(*ptyfd);
      return 0;
    }

  return 1;
  
#else /* HAVE_GETPSEUDOTTY */
#ifdef HAVE__GETPTY

  /* _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
     pty's automagically when needed */

  char *slave;

  slave = _getpty(ptyfd, O_RDWR, 0622, 0);
  if (slave == NULL)
    {
      error("_getpty: %.100s", strerror(errno));
      return 0;
    }
  strcpy(namebuf, slave);
  /* Open the slave side. */
  *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      error("%.200s: %.100s", namebuf, strerror(errno));
      close(*ptyfd);
      return 0;
    }
  return 1;

#else /* HAVE__GETPTY */
#ifdef HAVE_DEV_PTMX
  /* This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3 also has
     bsd-style ptys, but they simply do not work.) */

  int ptm;
  char *pts;
  
  ptm = open("/dev/ptmx", O_RDWR|O_NOCTTY);
  if (ptm < 0)
    {
      error("/dev/ptmx: %.100s", strerror(errno));
      return 0;
    }
  if (grantpt(ptm) < 0)
    {
      error("grantpt: %.100s", strerror(errno));
      return 0;
    }
  if (unlockpt(ptm) < 0)
    {
      error("unlockpt: %.100s", strerror(errno));
      return 0;
    }
  pts = ptsname(ptm);
  if (pts == NULL)
    error("Slave pty side name could not be obtained.");
  strcpy(namebuf, pts);
  *ptyfd = ptm;

  /* Open the slave side. */
  *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      error("%.100s: %.100s", namebuf, strerror(errno));
      close(*ptyfd);
      return 0;
    }
  /* Push the appropriate streams modules, as described in Solaris pts(7). */
  if (ioctl(*ttyfd, I_PUSH, "ptem") < 0)
    error("ioctl I_PUSH ptem: %.100s", strerror(errno));
  if (ioctl(*ttyfd, I_PUSH, "ldterm") < 0)
    error("ioctl I_PUSH ldterm: %.100s", strerror(errno));
#if 0 /* HPUX does not have this, causes ugly log entries.  Some systems need
	 this.  Let's not give any warnings if this fails. */
  if (ioctl(*ttyfd, I_PUSH, "ttcompat") < 0)
    error("ioctl I_PUSH ttcompat: %.100s", strerror(errno));
#else
  ioctl(*ttyfd, I_PUSH, "ttcompat");
#endif
  return 1;

#else /* HAVE_DEV_PTMX */
#ifdef HAVE_DEV_PTS_AND_PTC

  /* AIX-style pty code. */

  const char *name;

  *ptyfd = open("/dev/ptc", O_RDWR|O_NOCTTY);
  if (*ptyfd < 0)
    {
      error("Could not open /dev/ptc: %.100s", strerror(errno));
      return 0;
    }
  name = ttyname(*ptyfd);
  if (!name)
    fatal("Open of /dev/ptc returns device for which ttyname fails.");
  strcpy(namebuf, name);
  *ttyfd = open(name, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      error("Could not open pty slave side %.100s: %.100s", 
	    name, strerror(errno));
      close(*ptyfd);
      return 0;
    }
  return 1;

#else /* HAVE_DEV_PTS_AND_PTC */
#ifdef __hpux
  /* HP-UX pty cloning code. */

  const char *name;
  extern char * ptsname(int);
  
  *ptyfd = open("/dev/ptym/clone", O_RDWR|O_NOCTTY);
  if (*ptyfd < 0)
    {
      /* Not all releases have ptym/clone, so we also support the other way */
      
      char buf[64];
      register int loc;
      const char oletters[]= "onmlkjihgfecbazyxwvutsrqp";
      const char onumbers[]= "0123456789abcdef";
      const char letters[] = "pqrstuvwxyzabcefghijklmno";
      const char numbers[] = "0123456789";
      /*	ptys are created in this order:
      **              /dev/ptym/pty[p-z][0-f]
      **              /dev/ptym/pty[a-ce-o][0-f]
      **              /dev/ptym/pty[p-z][0-9][0-9]
      **              /dev/ptym/pty[a-ce-o][0-9][0-9]
      **              /dev/ptym/pty[a-ce-o][0-9][0-9][0-9]
      **      with /dev/ptym/pty[p-r][0-f] linked into /dev.  Search the
      **      ones in /dev last for old (unaware) applications
      */
      
      static const char *ptymdirs[]={"/dev/ptym/","/dev/", (const char *)NULL};
      
      for (loc=0;ptymdirs[loc] != (const char *)NULL;loc++) {
	register int ltr,num1,num2,num3,len;
	struct stat stb,stb2;
	if (stat(ptymdirs[loc],&stb))
	  continue;
	
	/* first try ptyp000-ptyo999 */
	strcpy(buf,ptymdirs[loc]);
	strcat(buf,"ptyp000");
	if (stat(buf,&stb) == 0) {
	  len=strlen(buf);
	  for (ltr=0;letters[ltr];ltr++) {
	    buf[len - 4] = letters[ltr];
	    for (num1=0;numbers[num1];num1++) {
	      buf[len - 3] = numbers[num1];
	      for (num2=0;numbers[num2];num2++) {
		buf[len - 2] = numbers[num2];
		for (num3=0;numbers[num3];num3++) {
		  buf[len - 1] = numbers[num3];
		  if ((*ptyfd=open(buf,O_RDWR|O_NOCTTY)) < 0)
		    continue;
		  name=ptsname(*ptyfd);
		  if (fstat(*ptyfd,&stb)<0 || stat(name,&stb2)<0 ||
		      minor(stb.st_rdev) != minor(stb2.st_rdev)) {
		    close (*ptyfd);
		    continue;
		  }
		  goto gotit;
		} /* num 3 */
	      } /* num 2 */
	    } /* num 1 */
	  } /* letter */
	} /* p000 exists */
	
	/* next try ptyp00-ptyo99 */
	strcpy(buf,ptymdirs[loc]);
	strcat(buf,"ptyp00");
	if (stat(buf,&stb) == 0) {
	  len=strlen(buf);
	  for (ltr=0;letters[ltr];ltr++) {
	    buf[len - 3] = letters[ltr];
	    for (num1=0;numbers[num1];num1++) {
	      buf[len - 2] = numbers[num1];
	      for (num2=0;numbers[num2];num2++) {
		buf[len - 1] = numbers[num2];
		if ((*ptyfd=open(buf,O_RDWR|O_NOCTTY)) < 0)
		  continue;
		name=ptsname(*ptyfd);
		if (fstat(*ptyfd,&stb)<0 || stat(name,&stb2)<0 ||
		    minor(stb.st_rdev) != minor(stb2.st_rdev)) {
		  close (*ptyfd);
		  continue;
		}
		goto gotit;
	      } /* num 2 */
	    } /* num 1 */
	  } /* letter */
	} /* p00 exists */

	/* next try ptyp0-ptyof */
	strcpy(buf,ptymdirs[loc]);
	strcat(buf,"ptyp0");
	len=strlen(buf);
	for (ltr=0;oletters[ltr];ltr++) {
	  buf[len - 2] = oletters[ltr];
	  for (num1=0;onumbers[num1];num1++) {
	    buf[len - 1] = onumbers[num1];
	    if ((*ptyfd=open(buf,O_RDWR|O_NOCTTY)) < 0)
	      continue;
	    name=ptsname(*ptyfd);
	    if (fstat(*ptyfd,&stb)<0 || stat(name,&stb2)<0 ||
		minor(stb.st_rdev) != minor(stb2.st_rdev)) {
	      close (*ptyfd);
	      continue;
	    }
	    goto gotit;
	  } /* num 1 */
	} /* letter */
      }	/* for directory */
    } /* clone open failed */

gotit:
  name = ptsname(*ptyfd);
  if (!name)
    fatal("Open of /dev/ptym/clone returns device for which ptsname fails.");
  *ttyfd = open(name, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      error("Could not open pty slave side %.100s: %.100s", 
	    name, strerror(errno));
      close(*ptyfd);
      return 0;
    }
  /* Doing the ttyname again and then the strcpy makes us agree with other
   * calls to ttyname.  (ptsname and ttyname may return different values...)
   */
  name = ttyname(*ttyfd);
  strcpy(namebuf, name);
  return 1;
#else
#ifdef CRAY
  char buf[64];
  int i;
  int highpty;

#ifdef _SC_CRAY_NPTY
  highpty=sysconf(_SC_CRAY_NPTY);
  if (highpty==-1) highpty=128;
#else
  highpty=128;
#endif

  for (i = 0; i < highpty; i++)
    {
      sprintf(buf, "/dev/pty/%03d", i);
      *ptyfd = open(buf, O_RDWR|O_NOCTTY);
      if (*ptyfd < 0)
	continue;
      sprintf(namebuf, "/dev/ttyp%03d", i);
      /* Open the slave side. */
      *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
      if (*ttyfd < 0)
	{
	  error("%.100s: %.100s", namebuf, strerror(errno));
	  close(*ptyfd);
	  return 0;
	}
      return 1;
    }
  return 0;

#else /* CRAY */  

  /* BSD-style pty code. */

#ifdef HAVE_DEV_PTYP10	/* SCO UNIX: similar to BSD, but different naming */
  char buf[64];
  int i;
  
  for (i=0; i<256; i++)	/* max 256 pty's possible */
    {
      sprintf(buf, "/dev/ptyp%d", i);
      *ptyfd = open(buf, O_RDWR|O_NOCTTY);
      if (*ptyfd < 0)
	{
          if (errno == ENODEV)	    /* all used up */
	    {
	      error("pty_allocate: all allocated ptys (%d) used", i);
	      return 0;
	    }
	  continue;
	}
      
      sprintf(namebuf, "/dev/ttyp%d", i);
      
      /* Open the slave side. */

      *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
      if (*ttyfd < 0)
	{
	  error("%.100s: %.100s", namebuf, strerror(errno));
	  close(*ptyfd);
	  return 0;
	}
      return 1;
    }
  
#else			/* not SCO UNIX */
  char buf[64];
  int i;
#ifdef __FreeBSD__
  const char *ptymajors = "pqrsPQRS";
  const char *ptyminors = "0123456789abcdefghijklmnopqrstuv";
#else
  const char *ptymajors = 
    "pqrstuvwxyzabcdefghijklmnoABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char *ptyminors = "0123456789abcdef";
#endif
  int num_minors = strlen(ptyminors);
  int num_ptys = strlen(ptymajors) * num_minors;

  for (i = 0; i < num_ptys; i++)
    {
      sprintf(buf, "/dev/pty%c%c", ptymajors[i / num_minors], 
	      ptyminors[i % num_minors]);
      *ptyfd = open(buf, O_RDWR|O_NOCTTY);
      if (*ptyfd < 0)
	continue;
      sprintf(namebuf, "/dev/tty%c%c", ptymajors[i / num_minors], 
	      ptyminors[i % num_minors]);

#ifdef HAVE_REVOKE
      if (revoke(namebuf) == -1)
 	error("pty_allocate: revoke failed for %.100s", namebuf);
#endif

      /* Open the slave side. */
      *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
      if (*ttyfd < 0)
	{
	  error("%.100s: %.100s", namebuf, strerror(errno));
	  close(*ptyfd);
	  return 0;
	}

#if defined(ultrix) || defined(NeXT)
      (void) signal(SIGTTOU, SIG_IGN);  /* corey via nancy */
#endif /* ultrix or NeXT */

      return 1;
    }
#endif /* SCO UNIX */
  return 0;
#endif /* CRAY */
#endif /* __hpux */
#endif /* HAVE_DEV_PTS_AND_PTC */
#endif /* HAVE_DEV_PTMX */
#endif /* HAVE__GETPTY */
#endif /* HAVE_GETPSEUDOTTY */
#endif /* HAVE_OPENPTY */
}

/* Releases the tty.  Its ownership is returned to root, and permissions to
   0666. */

void pty_release(const char *ttyname)
{
  if (chown(ttyname, (uid_t)UID_ROOT, (gid_t)0) < 0)
    debug("chown %.100s 0 0 failed: %.100s", ttyname, strerror(errno));
  if (chmod(ttyname, (mode_t)0666) < 0)
    debug("chmod %.100s 0666 failed: %.100s", ttyname, strerror(errno));
}

/* Makes the tty the processes controlling tty and sets it to sane modes. */

void pty_make_controlling_tty(int *ttyfd, const char *ttyname)
{
  int fd;

  /* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      (void)ioctl(fd, TIOCNOTTY, NULL);
      close(fd);
    }
#endif /* TIOCNOTTY */
  
  /* Verify that we are successfully disconnected from the controlling tty. */
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      error("Failed to disconnect from controlling tty.");
      close(fd);
    }

  /* Make it our controlling tty. */
#ifdef TIOCSCTTY
  debug("Setting controlling tty using TIOCSCTTY.");
  /* We ignore errors from this, because HPSUX defines TIOCSCTTY, but returns
     EINVAL with these arguments, and there is absolutely no documentation. */
  ioctl(*ttyfd, TIOCSCTTY, NULL);
#endif /* TIOCSCTTY */

#ifdef CRAY
  debug("Setting controlling tty using TCSETCTTY.");
  ioctl(*ttyfd, TCSETCTTY, NULL);
#endif

#ifdef HAVE_SETPGID
  /* This appears to be necessary on some machines...  */
  setpgid(0, 0);
#endif

  fd = open(ttyname, O_RDWR);
  if (fd < 0)
    error("%.100s: %.100s", ttyname, strerror(errno));
  else
    close(fd);

  /* Verify that we now have a controlling tty. */
  fd = open("/dev/tty", O_WRONLY);
  if (fd < 0)
    error("open /dev/tty failed - could not set controlling tty: %.100s",
	  strerror(errno));
  else
    {
      close(fd);
#if defined(HAVE_VHANGUP) && !defined(HAVE_REVOKE)
      signal(SIGHUP, SIG_IGN);
      vhangup();
      signal(SIGHUP, SIG_DFL);
      fd = open(ttyname, O_RDWR);
      if (fd == -1)
	error("pty_make_controlling_tty: reopening controlling tty after vhangup failed for %.100s",
	      ttyname);
      close(*ttyfd);
      *ttyfd = fd;
#endif /* HAVE_VHANGUP && !HAVE_REVOKE */
    }
}

/* Changes the window size associated with the pty. */

void pty_change_window_size(int ptyfd, int row, int col,
			    int xpixel, int ypixel)
{
#ifdef SIGWINCH
  struct winsize w;
  w.ws_row = row;
  w.ws_col = col;
  w.ws_xpixel = xpixel;  
  w.ws_ypixel = ypixel;
  (void)ioctl(ptyfd, TIOCSWINSZ, &w);
#endif /* SIGWINCH */
}

