/*

acconfig.h - template used by autoheader to create config.h.in
config.h.in - used by autoconf to create config.h
config.h - created by autoconf; contains defines generated by autoconf

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>

*/

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (char *)rcsid, "\100(#)" msg }

@TOP@

/* Define if you have SYSV-style /dev/ptmx and /dev/pts/. */
#undef HAVE_DEV_PTMX

/* Define if you have /dev/pts and /dev/ptc devices (as in AIX). */
#undef HAVE_DEV_PTS_AND_PTC

/* Define if you have shadow passwords in /etc/security/passwd (AIX style). */
#undef HAVE_ETC_SECURITY_PASSWD

/* Define if you have shadow passwords in /etc/security/passwd.adjunct
   (SunOS style). */
#undef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
  
/* Define if you have OSF1 C2 security installed on the system */
#undef HAVE_OSF1_C2_SECURITY

/* Define if you have shadow passwords in /etc/shadow (Solaris style). */
#undef HAVE_ETC_SHADOW

/* Define if you have system login defaults in /etc/default/login. */
#undef HAVE_ETC_DEFAULT_LOGIN

/* Define if utmp structure has host field. */
#undef HAVE_HOST_IN_UTMP

/* Define if utmp structure has addr field. */
#undef HAVE_ADDR_IN_UTMP

/* Define if utmp structure has id field. */
#undef HAVE_ID_IN_UTMP

/* Define if utmp structure has name field. */
#undef HAVE_NAME_IN_UTMP

/* Define if utmp structure has pid field. */
#undef HAVE_PID_IN_UTMP

/* Define if utmpx structure has ut_session. */
#undef HAVE_UT_SESSION

/* Define if utmpx structure has ut_syslen. */
#undef HAVE_UT_SYSLEN

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

/* This is defined if we found a lastlog file.  The presence of lastlog.h
   alone is not a sufficient indicator (at least newer BSD systems have
   lastlog but no lastlog.h. */
#undef HAVE_LASTLOG

/* Define this if libutil.a contains BSD 4.4 compatible login(), logout(),
   and logwtmp() calls. */
#undef HAVE_LIBUTIL_LOGIN

/* Location of system mail spool directory. */
#undef MAIL_SPOOL_DIRECTORY

/* Defined if mail goes to $HOME/newmail instead of a global mail spool. */
#undef HAVE_TILDE_NEWMAIL

/* Define this to be the default user path if you don't like the default. 
   See the --with-path=<path> configure option. */
#undef DEFAULT_PATH

/* Define this if O_NONBLOCK does not work on your system (e.g., Ultrix). */
#undef O_NONBLOCK_BROKEN

/* Define this if sys/syslog.h needs to be included in addition to syslog.h.
   This is the case on some Ultrix versions. */
#undef NEED_SYS_SYSLOG_H

/* Define this to include Blowfish encryption. */
#undef WITH_BLOWFISH

/* Define this to include libwrap (tcp_wrappers) support. */
#undef LIBWRAP

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

/* Define this if you are using HPSUX.  HPUX uses non-standard shared
   memory communication for X, which seems to be enabled by the display name
   matching that of the local host.  This circumvents it by using the IP
   address instead of the host name in DISPLAY. */
#undef HPSUX_NONSTANDARD_X11_KLUDGE

/* Define this if inet_network should be used instead of inet_addr.  This is
   the case on DGUX 5.4. */
#undef BROKEN_INET_ADDR

/* Define this if your system does not like sizeof(struct sockaddr_un) as the
   size argument in bind and connect calls for unix domain sockets. */
#undef USE_STRLEN_FOR_AF_UNIX

/* Define this to use pipes instead of socketpairs for communicating with the
   client program.  Socketpairs do not seem to work on all systems. */
#undef USE_PIPES

/* Directory containing ssh_config, ssh_known_hosts, sshd_pid, etc.  Normally
   /etc. */
#undef ETCDIR

/* Define this if speed_t is defined in stdtypes.h or otherwise gets included
   into ttymodes.c from system headers. */
#undef SPEED_T_IN_STDTYPES_H

/* Define this if compiling with SOCKS (the firewall traversal library).
   Also, you must define connect, getsockname, bind, accept, listen, and
   select to their R-versions. */
#undef SOCKS
#undef connect
#undef getsockname
#undef bind
#undef accept
#undef listen
#undef select

/* Define these if on SCO Unix. */
#undef HAVE_SCO_ETC_SHADOW
#undef SCO

/* Define this if you want to compile in Kerberos V4 support.
   This can be done at configure time with the --with-krb4 argument. */
#undef KRB4

/* Define this if you want to compile in AFS support.
   This can be done at configure time with the --with-afs argument. */
#undef AFS

/* Define this if you want to enable nonstandard krb4 TGT forwarding. */
#undef KERBEROS_TGT_PASSING

/* Define this if you want to add optional compression support. */
#undef WITH_ZLIB
