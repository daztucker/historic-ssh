/*

pty.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@ssh.fi>, Espoo, Finland
Copyright (c) 1995-1999 SSH Communications Security Oy, Espoo, Finland
                        All rights reserved

Created: Fri Mar 17 05:03:28 1995 ylo

Functions for allocating a pseudo-terminal and making it the controlling
tty.

*/

/*
 * $Id: pty.h,v 1.3 1999/11/17 17:04:50 tri Exp $
 * $Log: pty.h,v $
 * Revision 1.3  1999/11/17 17:04:50  tri
 * 	Fixed copyright notices.
 *
 * Revision 1.2  1997/04/21 01:03:30  kivinen
 *      Added pty_cleanup_proc prototype.
 *
 * Revision 1.1.1.1  1996/02/18 21:38:10  ylo
 *      Imported ssh-1.2.13.
 *
 * Revision 1.3  1995/07/16  01:03:40  ylo
 *      Added pty_release.
 *
 * Revision 1.2  1995/07/13  01:28:41  ylo
 *      Removed "Last modified" header.
 *      Added cvs log.
 *
 * $Endlog$
 */

#ifndef PTY_H
#define PTY_H

/* Allocates and opens a pty.  Returns 0 if no pty could be allocated,
   or nonzero if a pty was successfully allocated.  On success, open file
   descriptors for the pty and tty sides and the name of the tty side are 
   returned (the buffer must be able to hold at least 64 characters). */
int pty_allocate(int *ptyfd, int *ttyfd, char *ttyname);

/* Releases the tty.  Its ownership is returned to root, and permissions to
   0666. */
void pty_release(const char *ttyname);

/* Makes the tty the processes controlling tty and sets it to sane modes. 
   This may need to reopen the tty to get rid of possible eavesdroppers. */
void pty_make_controlling_tty(int *ttyfd, const char *ttyname);

/* Changes the window size associated with the pty. */
void pty_change_window_size(int ptyfd, int row, int col,
                            int xpixel, int ypixel);

/* Function to perform cleanup if we get aborted abnormally (e.g., due to a
   dropped connection). */
void pty_cleanup_proc(void *context);

#endif /* PTY_H */
