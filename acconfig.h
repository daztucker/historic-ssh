/*

acconfig.h - template used by autoheader to create config.h.in
config.h.in - used by autoconf to create config.h
config.h - created by autoconf; contains defines generated by autoconf

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>

*/

/*
 * $Log: acconfig.h,v $
 * Revision 1.3  1995/07/27  00:36:32  ylo
 * 	Added SSH_UTMP, SSH_WTMP, SSH_LASTLOG, DEFAUL_PATH.
 *
 * Revision 1.2  1995/07/13  01:08:48  ylo
 * 	Added cvs log.
 *
 * $Endlog$
 */

@TOP@

/* Define to use a unix-domain socket instead of an open file descriptor
   for communicating with the authentication agent. */
#undef AGENT_USES_SOCKET

/* Define if you have SYSV-style /dev/ptmx and /dev/pts/. */
#undef HAVE_DEV_PTMX

/* Define if you have /dev/pts and /dev/ptc devices (as in AIX). */
#undef HAVE_DEV_PTS_AND_PTC

/* Define if you have shadow passwords in /etc/master.passwd (NetBSD style). */
#undef HAVE_ETC_MASTER_PASSWD

/* Define if you have shadow passwords in /etc/security/passwd (AIX style). */
#undef HAVE_ETC_SECURITY_PASSWD

/* Define if you have shadow passwords in /etc/security/passwd.adjunct
   (SunOS style). */
#undef HAVE_ETC_SECURITY_PASSWD_ADJUNCT

/* Define if you have shadow passwords in /etc/shadow (Solaris style). */
#undef HAVE_ETC_SHADOW

/* Define if utmp structure has host field. */
#undef HAVE_HOST_IN_UTMP

/* Define if utmp structure has id field. */
#undef HAVE_ID_IN_UTMP

/* Define if utmp structure has name field. */
#undef HAVE_NAME_IN_UTMP

/* Define if utmp structure has pid field. */
#undef HAVE_PID_IN_UTMP

/* Define if /var/adm/lastlog or whatever it is called is a directory
   (e.g. SGI IRIX). */
#undef LASTLOG_IS_DIR

/* Define to disable .rhosts and /etc/hosts.equiv authentication in server. 
   However, .rhosts and /etc/hosts.equiv with RSA host authentication are
   not affected by this. */
#undef NO_RHOSTS_AUTHENTICATION

/* Define to use RSAREF. */
#undef RSAREF

/* Define this to be the path of the rsh program to support executing rsh. */
#undef RSH_PATH

/* Define this to be the path of the xauth program. */
#undef XAUTH_PATH

/* Default path for utmp.  Determined by configure. */
#undef SSH_UTMP

/* Default path for wtmp.  Determined by configure. */
#undef SSH_WTMP

/* Default path for lastlog.  Determined by configure. */
#undef SSH_LASTLOG

/* Define this to be the default user path if you don't like the default. 
   See the --with-path=<path> configure option. */
#undef DEFAULT_PATH
