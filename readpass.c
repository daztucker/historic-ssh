/*

readpass.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Jul 10 22:08:59 1995 ylo

Functions for reading passphrases and passwords.

*/

/*
 * $Id: readpass.c,v 1.6 1997/05/13 22:30:18 kivinen Exp $
 * $Log: readpass.c,v $
 * Revision 1.6  1997/05/13  22:30:18  kivinen
 * 	Added some casts.
 *
 * Revision 1.5  1997/04/17 04:01:52  kivinen
 * 	Added read_confirmation function.
 *
 * Revision 1.4  1997/04/05 21:49:28  kivinen
 * 	Fixed the '-quoting from \' to '\''.
 *
 * Revision 1.3  1997/03/26 07:15:23  kivinen
 * 	Fixed prompt quoting so ' will be quoted only if in command
 * 	line.
 *
 * Revision 1.2  1997/03/19 17:36:18  kivinen
 * 	Quote all unprintable characters in password prompt. Also
 * 	quote all '-characters.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:12  ylo
 * 	Imported ssh-1.2.13.
 *
 * Revision 1.2  1995/07/13  01:31:04  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "xmalloc.h"
#include "ssh.h"
#include "userfile.h"

/* Saved old terminal mode for read_passphrase. */
#ifdef USING_TERMIOS
static struct termios saved_tio;
#endif
#ifdef USING_SGTTY
static struct sgttyb saved_tio;
#endif

/* Old interrupt signal handler for read_passphrase. */
static RETSIGTYPE (*old_handler)(int sig) = NULL;

/* Interrupt signal handler for read_passphrase. */

RETSIGTYPE intr_handler(int sig)
{
  /* Restore terminal modes. */
#ifdef USING_TERMIOS
  tcsetattr(fileno(stdin), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(stdin), TIOCSETP, &saved_tio);
#endif
  /* Restore the old signal handler. */
  signal(sig, old_handler);
  /* Resend the signal, with the old handler. */
  kill(getpid(), sig);
}

/* Reads a passphrase from /dev/tty with echo turned off.  Returns the 
   passphrase (allocated with xmalloc).  Exits if EOF is encountered. 
   The passphrase if read from stdin if from_stdin is true (as is the
   case with ssh-keygen).  */

char *read_passphrase(uid_t uid, const char *prompt, int from_stdin)
{
  char buf[1024], *cp;
  unsigned char quoted_prompt[512];
  unsigned const char *p;
#ifdef USING_TERMIOS
  struct termios tio;
#endif
#ifdef USING_SGTTY
  struct sgttyb tio;
#endif
  FILE *f;
  UserFile uf;
  int i;
  
  if (from_stdin)
    f = stdin;
  else
    {
      /* Read the passphrase from /dev/tty to make it possible to ask it even 
	 when stdin has been redirected. */
      f = fopen("/dev/tty", "r");
      if (!f)
	{
	  if (getenv("DISPLAY"))
	    {
	      char command[512];
	      
	      fprintf(stderr,
		      "Executing ssh-askpass to query the password...\n");
	      fflush(stdout);
	      fflush(stderr);
	      for(p = (unsigned const char *) prompt, i = 0;
		  i < sizeof(quoted_prompt) - 5 && *p;
		  i++, p++)
		{
		  if (*p == '\'')
		    {
		      quoted_prompt[i++] = '\'';
		      quoted_prompt[i++] = '\\';
		      quoted_prompt[i++] = '\'';
		      quoted_prompt[i] = '\'';
		    }
		  else if (isprint(*p) || isspace(*p))
		    quoted_prompt[i] = *p;
		  else if (iscntrl(*p))
		    {
		      quoted_prompt[i++] = '^';
		      if (*p < ' ')
			quoted_prompt[i] = *p + '@';
		      else
			quoted_prompt[i] = '?';
		    }
		  else if (*p > 128)
		    quoted_prompt[i] = *p;
		}
	      quoted_prompt[i] = '\0';
  
	      sprintf(command, "ssh-askpass '%.400s'", quoted_prompt);
	      
	      uf = userfile_popen(uid, command, "r");
	      if (uf == NULL)
		{
		  fprintf(stderr, "Could not query passphrase: '%.200s' failed.\n",
			  command);
		  exit(1);
		}
	      if (!userfile_gets(buf, sizeof(buf), uf))
		{
		  userfile_pclose(uf);
		  fprintf(stderr, "No passphrase supplied.  Exiting.\n");
		  exit(1);
		}
	      userfile_pclose(uf);
	      if (strchr(buf, '\n'))
		*strchr(buf, '\n') = 0;
	      return xstrdup(buf);
	    }

	  /* No controlling terminal and no DISPLAY.  Nowhere to read. */
	  fprintf(stderr, "You have no controlling tty and no DISPLAY.  Cannot read passphrase.\n");
	  exit(1);
	}
    }

  for(p = (unsigned const char *) prompt, i = 0;
      i < sizeof(quoted_prompt) - 4 && *p; i++, p++)
    {
      if (isprint(*p) || isspace(*p))
	quoted_prompt[i] = *p;
      else if (iscntrl(*p))
	{
	  quoted_prompt[i++] = '^';
	  if (*p < ' ')
	    quoted_prompt[i] = *p + '@';
	  else
	    quoted_prompt[i] = '?';
	}
      else if (*p > 128)
	quoted_prompt[i] = *p;
    }
  quoted_prompt[i] = '\0';
  
  /* Display the prompt (on stderr because stdout might be redirected). */
  fflush(stdout);
  fprintf(stderr, "%s", quoted_prompt);
  fflush(stderr);

  /* Get terminal modes. */
#ifdef USING_TERMIOS
  tcgetattr(fileno(f), &tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(f), TIOCGETP, &tio);
#endif
  saved_tio = tio;
  /* Save signal handler and set the new handler. */
  old_handler = signal(SIGINT, intr_handler);

  /* Set new terminal modes disabling all echo. */
#ifdef USING_TERMIOS
  tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fileno(f), TCSANOW, &tio);
#endif
#ifdef USING_SGTTY
  tio.sg_flags &= ~(ECHO);
  ioctl(fileno(f), TIOCSETP, &tio);
#endif

  /* Read the passphrase from the terminal. */
  if (fgets(buf, sizeof(buf), f) == NULL)
    {
      /* Got EOF.  Just exit. */
      /* Restore terminal modes. */
#ifdef USING_TERMIOS
      tcsetattr(fileno(f), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
      ioctl(fileno(f), TIOCSETP, &saved_tio);
#endif
      /* Restore the signal handler. */
      signal(SIGINT, old_handler);
      /* Print a newline (the prompt probably didn\'t have one). */
      fprintf(stderr, "\n");
      /* Close the file. */
      if (f != stdin)
	fclose(f);
      exit(1);
    }
  /* Restore terminal modes. */
#ifdef USING_TERMIOS
  tcsetattr(fileno(f), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(f), TIOCSETP, &saved_tio);
#endif
  /* Restore the signal handler. */
  (void)signal(SIGINT, old_handler);
  /* Remove newline from the passphrase. */
  if (strchr(buf, '\n'))
    *strchr(buf, '\n') = 0;
  /* Allocate a copy of the passphrase. */
  cp = xstrdup(buf);
  /* Clear the buffer so we don\'t leave copies of the passphrase laying
     around. */
  memset(buf, 0, sizeof(buf));
  /* Print a newline since the prompt probably didn\'t have one. */
  fprintf(stderr, "\n");
  /* Close the file. */
  if (f != stdin)
    fclose(f);
  return cp;
}

/* Reads a yes/no confirmation from /dev/tty.  Exits if EOF or "no" is
   encountered. */

void read_confirmation(const char *prompt)
{
  char buf[1024], *p;
  FILE *f;
  
  if (isatty(fileno(stdin)))
    f = stdin;
  else
    {
      /* Read the passphrase from /dev/tty to make it possible to ask it even 
	 when stdin has been redirected. */
      f = fopen("/dev/tty", "r");
      if (!f)
	{
	  fprintf(stderr, "You have no controlling tty.  Cannot read confirmation.\n");
	  exit(1);
	}
    }

  /* Read the passphrase from the terminal. */
  do
    {
      /* Display the prompt (on stderr because stdout might be redirected). */
      fflush(stdout);
      fprintf(stderr, "%s", prompt);
      fflush(stderr);
      /* Read line */
      if (fgets(buf, sizeof(buf), f) == NULL)
	{
	  /* Got EOF.  Just exit. */
	  /* Print a newline (the prompt probably didn\'t have one). */
	  fprintf(stderr, "\n");
	  fprintf(stderr, "Aborted by user");
	  /* Close the file. */
	  if (f != stdin)
	    fclose(f);
	  exit(1);
	}
      p = buf + strlen(buf) - 1;
      while (p > buf && isspace(*p))
	*p-- = '\0';
      p = buf;
      while (*p && isspace(*p))
	p++;
      if (strcmp(p, "no") == 0)
	{
	  /* Close the file. */
	  if (f != stdin)
	    fclose(f);
	  exit(1);
	}
    } while (strcmp(p, "yes") != 0);
  /* Close the file. */
  if (f != stdin)
    fclose(f);
}
