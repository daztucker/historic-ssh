/*

acconfig.h - template used by autoheader to create config.h.in
config.h.in - used by autoconf to create config.h
config.h - created by autoconf; contains defines generated by autoconf

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>

*/

/*
 * $Log: acconfig.h,v $
 * Revision 1.8  1995/09/06  15:57:37  ylo
 * 	Added BROKEN_INET_ADDR
 *
 * Revision 1.7  1995/08/29  22:17:54  ylo
 * 	Removed AGENT_USES_SOCKET
 * 	Added HPSUX_BROKEN_PTYS
 *
 * Revision 1.6  1995/08/21  23:20:17  ylo
 * 	Removed NO_RHOSTS_AUTHENTICATION.
 * 	Fixed a typo.
 *
 * Revision 1.5  1995/08/18  23:42:14  ylo
 * 	Added HAVE_SECURID.
 *
 * Revision 1.4  1995/08/18  22:41:46  ylo
 * 	Added O_NONBLOCK_BROKEN, WITHOUT_IDEA, crypt, __FreeBSD__, TTY_GROUP.
 *
 * Revision 1.3  1995/07/27  00:36:32  ylo
 * 	Added SSH_UTMP, SSH_WTMP, SSH_LASTLOG, DEFAUL_PATH.
 *
 * Revision 1.2  1995/07/13  01:08:48  ylo
 * 	Added cvs log.
 *
 * $Endlog$
 */

@TOP@

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

/* Define this if O_NONBLOCK does not work on your system (e.g., Ultrix). */
#undef O_NONBLOCK_BROKEN

/* Define this to leave out IDEA encryption. */
#undef WITHOUT_IDEA

/* This is defined to pw_encrypt on Linux when using John Faugh's shadow 
   password implementation. */
#undef crypt

/* This is defined on 386BSD to preted we are on FreeBSD. */
#undef __FreeBSD__

/* If defines, this overrides "tty" as the terminal group. */
#undef TTY_GROUP

/* Define this if you want to support Security Dynammics SecurID
   cards. */
#undef HAVE_SECURID

/* Define this if you have HPUX.  HPSUX has broken ptys (EOF is not passed
   from the slave side to the master side). */
#undef HPSUX_BROKEN_PTYS

/* Define this if inet_network should be used instead of inet_addr.  This is
   the case on DGUX 5.4. */
#undef BROKEN_INET_ADDR
