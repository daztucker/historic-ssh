/*

pty.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar 17 05:03:28 1995 ylo
Last modified: Wed Jun 21 22:12:21 1995 ylo

*/

#ifndef PTY_H
#define PTY_H

/* Allocates and opens a pty.  Returns 0 if no pty could be allocated,
   or nonzero if a pty was successfully allocated.  On success, open file
   descriptors for the pty and tty sides and the name of the tty side are 
   returned (the buffer must be able to hold at least 64 characters). */
int pty_allocate(int *ptyfd, int *ttyfd, char *ttyname);

/* Makes the tty the processes controlling tty and sets it to sane modes. 
   This may need to reopen the tty to get rid of possible eavesdroppers. */
void pty_make_controlling_tty(int *ttyfd, const char *ttyname);

/* Changes the window size associated with the pty. */
void pty_change_window_size(int ptyfd, int row, int col,
			    int xpixel, int ypixel);

#endif /* PTY_H */