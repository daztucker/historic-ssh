/*

uidswap.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Sep  9 01:56:14 1995 ylo

Code for uid-swapping.

*/

/*
 * $Id: uidswap.c,v 1.3 1995/09/11 17:36:26 ylo Exp $
 * $Log: uidswap.c,v $
 * Revision 1.3  1995/09/11  17:36:26  ylo
 * 	Removed support for setreuid().  It is deprecated in bsd 4.4.  Too bad.
 *
 * Revision 1.2  1995/09/09  21:30:23  ylo
 * 	Removed Last Modified; added cvs log.
 *
 * $EndLog$
 */

#include "includes.h"
#include "ssh.h"
#include "uidswap.h"

/* Note: all these functions must work in all of the following cases:

   1. euid=0, ruid=0
   2. euid=0, ruid!=0
   3. euid!=0, ruid!=0

   Additionally, they must work regardless of whether the system has
   POSIX saved uids or not. */

#ifdef HAVE_SETEUID

/* Temporarily changes to the given uid.  If the effective user id is not
   root, this does nothing.  This call cannot be nested. */

void temporarily_use_uid(uid_t uid)
{
  /* Propagate the privileged uid to all of our uids. */
  if (setuid(geteuid()) < 0)
    error("setuid %d: %.100s", (int)geteuid(), strerror(errno));

  /* Set the effective uid to the given (unprivileged) uid. */
  if (seteuid(uid) == -1)
    error("seteuid %d: %.100s", (int)uid, strerror(errno));
}

/* Restores to the original uid. */

void restore_uid()
{
  /* We are unable to restore the real uid to its unprivileged value. */
  /* Propagate the real uid (usually more privileged) to effective uid
     as well. */
  setuid(getuid());
}

/* Permanently sets all uids to the given uid.  This cannot be called while
   temporarily_use_uid is effective. */

void permanently_set_uid(uid_t uid)
{
  if (setuid(uid) < 0)
    error("setuid %d: %.100s", (int)uid, strerror(errno));
}

#else /* HAVE_SETEUID */

YOUR_SYSTEM_DOES_NOT_PERMIT_UID_SWAPPING_READ_AND_EDIT_UIDSWAP_C;
/* If we ever come here, if means that your system does not support any of
   the uid swapping methods we are aware of.  Tough.  This means that
   ssh will have to read certain files as root, which causes some security
   problems.  Unless your are very concerned about security, you can
   comment out the above line.  The effect is that local users on your
   machine might be able to read each other's files.  Also, you may encounter
   problems if home directories are on a NFS volume.  You may also
   encounter other problems; please don't complain unless you have some idea
   how to fix it. */

void temporarily_use_uid(uid_t uid)
{
}

void restore_uid()
{
}

void permanently_set_uid(uid_t uid)
{
  if (setuid(uid) < 0)
    error("setuid %d: %.100s", (int)uid, strerror(errno));
}

#endif /* HAVE_SETEUID */
