/*

scp - secure remote copy.  This is basically patched BSD rcp which uses ssh
to do the data transfer (instead of using rcmd).

NOTE: This version should NOT be suid root.  (This uses ssh to do the transfer
and ssh has the necessary privileges.)

1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
     
*/

/*
 * $Id: scp.c,v 1.8 1997/06/04 13:52:52 kivinen Exp $
 * $Log: scp.c,v $
 * Revision 1.8  1997/06/04 13:52:52  kivinen
 * 	Moved ssh_options before other options so you can override
 * 	options given by scp.
 *
 * Revision 1.7  1997/04/23 00:03:04  kivinen
 * 	Added -S flag
 *
 * Revision 1.6  1997/04/17 04:20:06  kivinen
 * *** empty log message ***
 *
 * Revision 1.5  1997/03/26 07:15:57  kivinen
 * 	Use last @ to separate user from host in the user@host@host:
 *
 * Revision 1.4  1997/03/19 17:37:37  kivinen
 * 	If configured ssh_program isn't found try if ssh can be found
 * 	in the same directory as scp and if so use that one. Fixed
 * 	typo:  execvp("ss", ...) -> execvp("ssh", ...).
 *
 * Revision 1.3  1996/11/24 08:24:36  kivinen
 * 	Added code that will try to run ssh from path if builtin path
 * 	fails.
 *
 * Revision 1.2  1996/11/07 18:17:56  kivinen
 * 	Added #ifndef _PATH_CP around #define _PATH_CP.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:11  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.9  1995/10/02  01:26:02  ylo
 * 	Fixed code for no HAVE_FCHMOD case.
 *
 * Revision 1.8  1995/09/27  02:14:56  ylo
 * 	Added support for SCO.
 *
 * Revision 1.7  1995/09/13  12:00:30  ylo
 * 	Don't use -l unless user name is explicitly given (so that
 * 	User works in .ssh/config).
 *
 * Revision 1.6  1995/08/18  22:55:53  ylo
 * 	Added utimbuf kludges for NextStep.
 * 	Added "-P port" option.
 *
 * Revision 1.5  1995/07/27  00:40:02  ylo
 * 	Include utime.h only if it exists.
 * 	Disable FallBackToRsh when running ssh from scp.
 *
 * Revision 1.4  1995/07/13  09:54:37  ylo
 * 	Added Snabb's patches for IRIX 4 (SVR3) (HAVE_ST_BLKSIZE code).
 *
 * Revision 1.3  1995/07/13  01:37:41  ylo
 * 	Added cvs log.
 *
 * $Endlog$
 */

/*
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: scp.c,v 1.8 1997/06/04 13:52:52 kivinen Exp $
 */

#ifndef lint
char scp_berkeley_copyright[] =
"@(#) Copyright (c) 1983, 1990, 1992, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#include "includes.h"
#include "ssh.h"
#include "xmalloc.h"
#ifdef HAVE_UTIME_H
#include <utime.h>
#if defined(_NEXT_SOURCE) && !defined(_POSIX_SOURCE)
struct utimbuf {
  time_t actime;
  time_t modtime;
};
#endif /* _NEXT_SOURCE */
#else
struct utimbuf
{
  long actime;
  long modtime;
};
#endif

#ifndef _PATH_CP
#define _PATH_CP "cp"
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

/* This is set to non-zero to enable verbose mode. */
int verbose = 0;

/* This is set to non-zero if compression is desired. */
int compress = 0;

/* This is set to non-zero if running in batch mode (that is, password
   and passphrase queries are not allowed). */
int batchmode = 0;

/* This is set to the cipher type string if given on the command line. */
char *cipher = NULL;

/* This is set to the RSA authentication identity file name if given on 
   the command line. */
char *identity = NULL;

/* This is the port to use in contacting the remote site (is non-NULL). */
char *port = NULL;

char *ssh_program = SSH_PROGRAM;

/* Ssh options */
char **ssh_options = NULL;
int ssh_options_cnt = 0;
int ssh_options_alloc = 0;

/* This function executes the given command as the specified user on the given
   host.  This returns < 0 if execution fails, and >= 0 otherwise.
   This assigns the input and output file descriptors on success. */

int do_cmd(char *host, char *remuser, char *cmd, int *fdin, int *fdout)
{
  int pin[2], pout[2], reserved[2];

  if (verbose)
    fprintf(stderr, "Executing: host %s, user %s, command %s\n",
	    host, remuser ? remuser : "(unspecified)", cmd);

  /* Reserve two descriptors so that the real pipes won't get descriptors
     0 and 1 because that will screw up dup2 below. */
  pipe(reserved);

  /* Create a socket pair for communicating with ssh. */
  if (pipe(pin) < 0)
    fatal("pipe: %s", strerror(errno));
  if (pipe(pout) < 0)
    fatal("pipe: %s", strerror(errno));

  /* Free the reserved descriptors. */
  close(reserved[0]);
  close(reserved[1]);

  /* For a child to execute the command on the remote host using ssh. */
  if (fork() == 0) 
    {
      char *args[256];
      unsigned int i, j;

      /* Child. */
      close(pin[1]);
      close(pout[0]);
      dup2(pin[0], 0);
      dup2(pout[1], 1);
      close(pin[0]);
      close(pout[1]);

      i = 0;
      args[i++] = ssh_program;
      for(j = 0; j < ssh_options_cnt; j++)
	{
	  args[i++] = "-o";
	  args[i++] = ssh_options[j];
	  if (i > 250)
	    fatal("Too many -o options (total number of arguments is more than 256)");
	}
      args[i++] = "-x";
      args[i++] = "-a";
      args[i++] = "-oFallBackToRsh no";
      args[i++] = "-oClearAllForwardings yes";
      if (verbose)
	args[i++] = "-v";
      if (compress)
	args[i++] = "-C";
      if (batchmode)
	args[i++] = "-oBatchMode yes";
      if (cipher != NULL)
	{
	  args[i++] = "-c";
	  args[i++] = cipher;
	}
      if (identity != NULL)
	{
	  args[i++] = "-i";
	  args[i++] = identity;
	}
      if (port != NULL)
	{
	  args[i++] = "-p";
	  args[i++] = port;
	}
      if (remuser != NULL)
	{
	  args[i++] = "-l";
	  args[i++] = remuser;
	}
      args[i++] = host;
      args[i++] = cmd;
      args[i++] = NULL;

      execvp(ssh_program, args);
      if (errno == ENOENT)
	{
	  args[0] = "ssh";
	  execvp("ssh", args);
	}
      perror(ssh_program);
      exit(1);
    }
  /* Parent.  Close the other side, and return the local side. */
  close(pin[0]);
  *fdout = pin[1];
  close(pout[1]);
  *fdin = pout[0];
  return 0;
}

void fatal(const char *fmt, ...)
{
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);
  fprintf(stderr, "%s\n", buf);
  exit(255);
}

/* This stuff used to be in BSD rcp extern.h. */

typedef struct {
	int cnt;
	char *buf;
} BUF;

extern int iamremote;

BUF	*allocbuf(BUF *, int, int);
char	*colon(char *);
void	 lostconn(int);
void	 nospace(void);
int	 okname(char *);
void	 run_err(const char *, ...);
void	 verifydir(char *);

/* Stuff from BSD rcp.c continues. */

struct passwd *pwd;
uid_t	userid;
int errs, remin, remout;
int pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

int	 response(void);
void	 rsource(char *, struct stat *);
void	 sink(int, char *[]);
void	 source(int, char *[]);
void	 tolocal(int, char *[]);
void	 toremote(char *, int, char *[]);
void	 usage(void);

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch, fflag, tflag;
	char *targ;
	extern char *optarg;
	extern int optind;
	struct stat st;

	if (stat(ssh_program, &st) < 0)
	  {
	    int len;
	    len = strlen(argv[0]);
	    if (len >= 3 && strcmp(argv[0] + len - 3, "scp") == 0)
	      {
		char *p;
		p = xstrdup(argv[0]);
		strcpy(p + len - 3, "ssh");
		if (stat(p, &st) < 0)
		  xfree(p);
		else
		  ssh_program = p;
	      }
	  }

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, "dfprtvBCc:i:P:o:S:")) != EOF)
		switch(ch) {			/* User-visible flags. */
		case 'S':
	       		ssh_program = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'P':
		  	port = optarg;
		  	break;
		case 'o':
		  	if (ssh_options_cnt >= ssh_options_alloc)
			  {
			    if (ssh_options_alloc == 0)
			      {
				ssh_options_alloc = 10;
				ssh_options = xmalloc(sizeof(char *) *
						      ssh_options_alloc);
			      }
			    else
			      {
				ssh_options_alloc += 10;
				ssh_options = xrealloc(ssh_options,
						       sizeof(char *) *
						       ssh_options_alloc);
			      }
			  }
			ssh_options[ssh_options_cnt++] = optarg;
			break;
			
		case 'r':
			iamrecursive = 1;
			break;
						/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':			/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':			/* "to" */
			iamremote = 1;
			tflag = 1;
			break;
		case 'c':
			cipher = optarg;
		  	break;
		case 'i':
		  	identity = optarg;
			break;
		case 'v':
			verbose = 1;
		  	break;
		case 'B':
		  	batchmode = 1;
		  	break;
		case 'C':
		  	compress = 1;
		  	break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %d", (int)userid);

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	if (fflag) {			/* Follow "protocol", send data. */
		(void)response();
		source(argc, argv);
		exit(errs != 0);
	}

	if (tflag) {			/* Receive data. */
		sink(argc, argv);
		exit(errs != 0);
	}

	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	/* Command to be executed on remote system using "ssh". */
  	(void)sprintf(cmd, "scp%s%s%s%s", verbose ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void)signal(SIGPIPE, lostconn);

	if ((targ = colon(argv[argc - 1])))	/* Dest is remote host. */
		toremote(targ, argc, argv);
	else {
		tolocal(argc, argv);		/* Dest is local host. */
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
	}
	exit(errs != 0);
}

void
toremote(targ, argc, argv)
	char *targ, *argv[];
	int argc;
{
	int i, len;
	char *bp, *host, *src, *suser, *thost, *tuser;

	*targ++ = 0;
	if (*targ == 0)
		targ = ".";

	if ((thost = strrchr(argv[argc - 1], '@'))) {
		/* user@host */
		*thost++ = 0;
		tuser = argv[argc - 1];
		if (*tuser == '\0')
			tuser = NULL;
		else if (!okname(tuser))
			exit(1);
	} else {
		thost = argv[argc - 1];
		tuser = NULL;
	}

	for (i = 0; i < argc - 1; i++) {
		src = colon(argv[i]);
		if (src) {			/* remote to remote */
		  	int j, options_len;
			char *options;
			
			options_len = 0;
			for(j = 0; j < ssh_options_cnt; j++)
			  options_len = 5 + strlen(ssh_options[j]);
			
			options = xmalloc(options_len + 1);
			options[0] = '\0';
			
			for(j = 0; j < ssh_options_cnt; j++)
			  {
			    strcat(options, "-o'");
			    strcat(options, ssh_options[j]);
			    strcat(options, "' ");
			  }
			*src++ = 0;
			if (*src == 0)
				src = ".";
			host = strrchr(argv[i], '@');
			len = strlen(ssh_program) + strlen(argv[i]) +
			    strlen(src) + (tuser ? strlen(tuser) : 0) +
			    strlen(thost) + strlen(targ) + CMDNEEDS + 32 +
			    options_len;
		        bp = xmalloc(len);
			if (host) {
				*host++ = 0;
				suser = argv[i];
				if (*suser == '\0')
					suser = pwd->pw_name;
				else if (!okname(suser))
					continue;
				(void)sprintf(bp, 
				    "%s%s %s -x -o'FallBackToRsh no' -o'ClearAllForwardings yes' -n -l %s %s %s %s '%s%s%s:%s'",
				    ssh_program, verbose ? " -v" : "", options,
				    suser, host, cmd, src,
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
			} else
				(void)sprintf(bp,
				    "exec %s%s %s -x -o'FallBackToRsh no' -o'ClearAllForwardings yes' -n %s %s %s '%s%s%s:%s'",
				    ssh_program, verbose ? " -v" : "", options,
				    argv[i], cmd, src,
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
		        if (verbose)
			  fprintf(stderr, "Executing: %s\n", bp);
			(void)system(bp);
			(void)xfree(bp);
		} else {			/* local to remote */
			if (remin == -1) {
				len = strlen(targ) + CMDNEEDS + 20;
			        bp = xmalloc(len);
				(void)sprintf(bp, "%s -t %s", cmd, targ);
				host = thost;
				if (do_cmd(host,  tuser,
					   bp, &remin, &remout) < 0)
				  exit(1);
				if (response() < 0)
					exit(1);
				(void)xfree(bp);
			}
			source(1, argv+i);
		}
	}
}

void
tolocal(argc, argv)
	int argc;
	char *argv[];
{
	int i, len;
	char *bp, *host, *src, *suser;

	for (i = 0; i < argc - 1; i++) {
		if (!(src = colon(argv[i]))) {		/* Local to local. */
			len = strlen(_PATH_CP) + strlen(argv[i]) +
			    strlen(argv[argc - 1]) + 20;
			bp = xmalloc(len);
			(void)sprintf(bp, "exec %s%s%s %s %s", _PATH_CP,
			    iamrecursive ? " -r" : "", pflag ? " -p" : "",
			    argv[i], argv[argc - 1]);
	  		if (verbose)
			  fprintf(stderr, "Executing: %s\n", bp);
			if (system(bp))
				++errs;
			(void)xfree(bp);
			continue;
		}
		*src++ = 0;
		if (*src == 0)
			src = ".";
		if ((host = strrchr(argv[i], '@')) == NULL) {
			host = argv[i];
			suser = NULL;
		} else {
			*host++ = 0;
			suser = argv[i];
			if (*suser == '\0')
				suser = pwd->pw_name;
			else if (!okname(suser))
				continue;
		}
		len = strlen(src) + CMDNEEDS + 20;
	        bp = xmalloc(len);
		(void)sprintf(bp, "%s -f %s", cmd, src);
	  	if (do_cmd(host, suser, bp, &remin, &remout) < 0) {
		  (void)xfree(bp);
		  ++errs;
		  continue;
		}
	  	xfree(bp);
		sink(1, argv + argc - 1);
		(void)close(remin);
		remin = remout = -1;
	}
}

void
source(argc, argv)
	int argc;
	char *argv[];
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i;
	int amt, fd, haderr, indx, result;
	char *last, *name, buf[2048];

	for (indx = 0; indx < argc; ++indx) {
                name = argv[indx];
		if ((fd = open(name, O_RDONLY, 0)) < 0)
			goto syserr;
		if (fstat(fd, &stb) < 0) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		switch (stb.st_mode & S_IFMT) {
		case S_IFREG:
			break;
		case S_IFDIR:
			if (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		if ((last = strrchr(name, '/')) == NULL)
			last = name;
		else
			++last;
		if (pflag) {
			/*
			 * Make it compatible with possible future
			 * versions expecting microseconds.
			 */
			(void)sprintf(buf, "T%lu 0 %lu 0\n",
				      (unsigned long)stb.st_mtime, 
				      (unsigned long)stb.st_atime);
			(void)write(remout, buf, strlen(buf));
			if (response() < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		(void)sprintf(buf, "C%04o %lu %s\n",
			      (unsigned int)(stb.st_mode & FILEMODEMASK), 
			      (unsigned long)stb.st_size, 
			      last);
	        if (verbose)
		  {
		    fprintf(stderr, "Sending file modes: %s", buf);
		    fflush(stderr);
		  }
		(void)write(remout, buf, strlen(buf));
		if (response() < 0)
			goto next;
		if ((bp = allocbuf(&buffer, fd, 2048)) == NULL) {
next:			(void)close(fd);
			continue;
		}

		/* Keep writing after an error so that we stay sync'd up. */
		for (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > stb.st_size)
				amt = stb.st_size - i;
			if (!haderr) {
				result = read(fd, bp->buf, amt);
				if (result != amt)
					haderr = result >= 0 ? EIO : errno;
			}
			if (haderr)
				(void)write(remout, bp->buf, amt);
			else {
				result = write(remout, bp->buf, amt);
				if (result != amt)
					haderr = result >= 0 ? EIO : errno;
			}
		}
		if (close(fd) < 0 && !haderr)
			haderr = errno;
		if (!haderr)
			(void)write(remout, "", 1);
		else
			run_err("%s: %s", name, strerror(haderr));
		(void)response();
	}
}

void
rsource(name, statp)
	char *name;
	struct stat *statp;
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[1100];

	if (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == 0)
		last = name;
	else
		last++;
	if (pflag) {
		(void)sprintf(path, "T%lu 0 %lu 0\n",
			      (unsigned long)statp->st_mtime, 
			      (unsigned long)statp->st_atime);
		(void)write(remout, path, strlen(path));
		if (response() < 0) {
			closedir(dirp);
			return;
		}
	}
	(void)sprintf(path, 
	    "D%04o %d %.1024s\n", (unsigned int)(statp->st_mode & FILEMODEMASK),
		      0, last);
  	if (verbose)
	  fprintf(stderr, "Entering directory: %s", path);
	(void)write(remout, path, strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp))) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void)sprintf(path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void)closedir(dirp);
	(void)write(remout, "E\n", 2);
	(void)response();
}

void
sink(argc, argv)
	int argc;
	char *argv[];
{
	static BUF buffer;
	struct stat stb;
	enum { YES, NO, DISPLAYED } wrerr;
	BUF *bp;
	off_t i, j;
	int amt, count, exists, first, mask, mode, ofd, omode;
	int setimes, size, targisdir, wrerrno = 0;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048];
  	struct utimbuf ut;
  	int dummy_usec;

#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void)umask(mask);
	if (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);
        
	(void)write(remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	for (first = 1;; first = 0) {
		cp = buf;
		if (read(remin, cp, 1) <= 0)
			return;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (read(remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0)
				(void)write(STDERR_FILENO,
				    buf + 1, strlen(buf + 1));
			if (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		if (buf[0] == 'E') {
			(void)write(remout, "", 1);
			return;
		}

		if (ch == '\n')
			*--cp = 0;

#define getnum(t) (t) = 0; \
  while (*cp >= '0' && *cp <= '9') (t) = (t) * 10 + (*cp++ - '0');
		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			getnum(ut.modtime);
			if (*cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			getnum(dummy_usec);
			if (*cp++ != ' ')
				SCREWUP("mtime.usec not delimited");
			getnum(ut.actime);
			if (*cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			getnum(dummy_usec);
			if (*cp++ != '\0')
				SCREWUP("atime.usec not delimited");
			(void)write(remout, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

	        for (size = 0; *cp >= '0' && *cp <= '9';)
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if (targisdir) {
			static char *namebuf;
			static int cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize)
			  namebuf = xmalloc(need);
			(void)sprintf(namebuf, "%s%s%s", targ,
			    *targ ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			int mod_flag = pflag;
			if (exists) {
				if (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void)chmod(np, mode);
			} else {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				if (mkdir(np, mode | S_IRWXU) < 0)
					goto bad;
			}
			vect[0] = np;
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				if (utime(np, &ut) < 0)
				    run_err("%s: set times: %s",
					np, strerror(errno));
			}
			if (mod_flag)
				(void)chmod(np, mode);
			continue;
		}
		omode = mode;
		mode |= S_IWRITE;
#ifdef HAVE_FTRUNCATE
	        /* Don't use O_TRUNC so the file doesn't get corrupted if
		   copying on itself. */
		ofd = open(np, O_WRONLY|O_CREAT, mode);
#else /* HAVE_FTRUNCATE */
		ofd = open(np, O_WRONLY|O_CREAT|O_TRUNC, mode);
#endif /* HAVE_FTRUNCATE */
		if (ofd < 0) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void)write(remout, "", 1);
		if ((bp = allocbuf(&buffer, ofd, 4096)) == NULL) {
			(void)close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = NO;
		for (count = i = 0; i < size; i += 4096) {
			amt = 4096;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = read(remin, cp, amt);
				if (j <= 0) {
					run_err("%s", j ? strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);
			if (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				if (wrerr == NO) {
					j = write(ofd, bp->buf, count);
					if (j != count) {
						wrerr = YES;
						wrerrno = j >= 0 ? EIO : errno; 
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		if (count != 0 && wrerr == NO &&
		    (j = write(ofd, bp->buf, count)) != count) {
			wrerr = YES;
			wrerrno = j >= 0 ? EIO : errno; 
		}
#ifdef HAVE_FTRUNCATE
		if (ftruncate(ofd, size)) {
			run_err("%s: truncate: %s", np, strerror(errno));
			wrerr = DISPLAYED;
		}
#endif /* HAVE_FTRUNCATE */
		if (pflag) {
			if (exists || omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode))
#else /* HAVE_FCHMOD */
				if (chmod(np, omode))
#endif /* HAVE_FCHMOD */
					run_err("%s: set mode: %s",
					    np, strerror(errno));
		} else {
			if (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode & ~mask))
#else /* HAVE_FCHMOD */
				if (chmod(np, omode & ~mask))
#endif /* HAVE_FCHMOD */
					run_err("%s: set mode: %s",
					    np, strerror(errno));
		}
		(void)close(ofd);
		(void)response();
		if (setimes && wrerr == NO) {
			setimes = 0;
			if (utime(np, &ut) < 0) {
				run_err("%s: set times: %s",
				    np, strerror(errno));
				wrerr = DISPLAYED;
			}
		}
		switch(wrerr) {
		case YES:
			run_err("%s: %s", np, strerror(wrerrno));
			break;
		case NO:
			(void)write(remout, "", 1);
			break;
		case DISPLAYED:
			break;
		}
	}
screwup:
	run_err("protocol error: %s", why);
	exit(1);
}

int
response()
{
	char ch, *cp, resp, rbuf[2048];

	if (read(remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch(resp) {
	case 0:				/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:				/* error, followed by error msg */
	case 2:				/* fatal error, "" */
		do {
			if (read(remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		if (!iamremote)
			(void)write(STDERR_FILENO, rbuf, cp - rbuf);
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage()
{
	(void)fprintf(stderr,
	    "usage: scp [-p] f1 f2; or: scp [-pr] f1 ... fn directory\n");
	exit(1);
}

void
run_err(const char *fmt, ...)
{
	static FILE *fp;
	va_list ap;
	va_start(ap, fmt);

	++errs;
	if (fp == NULL && !(fp = fdopen(remout, "w")))
		return;
	(void)fprintf(fp, "%c", 0x01);
	(void)fprintf(fp, "scp: ");
	(void)vfprintf(fp, fmt, ap);
	(void)fprintf(fp, "\n");
	(void)fflush(fp);

	if (!iamremote)
	  {
	    vfprintf(stderr, fmt, ap);
	    fprintf(stderr, "\n");
	  }

	va_end(ap);
}

/* Stuff below is from BSD rcp util.c. */

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: scp.c,v 1.8 1997/06/04 13:52:52 kivinen Exp $
 */

char *
colon(cp)
	char *cp;
{
	if (*cp == ':')		/* Leading colon is part of file name. */
		return (0);

	for (; *cp; ++cp) {
		if (*cp == ':')
			return (cp);
		if (*cp == '/')
			return (0);
	}
	return (0);
}

void
verifydir(cp)
	char *cp;
{
	struct stat stb;

	if (!stat(cp, &stb)) {
		if (S_ISDIR(stb.st_mode))
			return;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	exit(1);
}

int
okname(cp0)
	char *cp0;
{
	int c;
	char *cp;

	cp = cp0;
	do {
		c = *cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-' &&
		    c != '@' && c != '%' && c != '.' && c != '/')
			goto bad;
	} while (*++cp);
	return (1);

bad:	fprintf(stderr, "%s: invalid user name", cp0);
	return (0);
}

BUF *
allocbuf(bp, fd, blksize)
	BUF *bp;
	int fd, blksize;
{
	size_t size;
#ifdef HAVE_ST_BLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) < 0) {
		run_err("fstat: %s", strerror(errno));
		return (0);
	}
        if (stb.st_blksize == 0)
	  size = blksize;
        else
  	  size = blksize + (stb.st_blksize - blksize % stb.st_blksize) %
	  stb.st_blksize;
#else /* HAVE_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_ST_BLKSIZE */
	if (bp->cnt >= size)
		return (bp);
  	if (bp->buf == NULL)
	  bp->buf = xmalloc(size);
  	else
	  bp->buf = xrealloc(bp->buf, size);
	bp->cnt = size;
	return (bp);
}

void
lostconn(signo)
	int signo;
{
	if (!iamremote)
		fprintf(stderr, "lost connection\n");
	exit(1);
}
