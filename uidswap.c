/*

uidswap.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Sep  9 01:56:14 1995 ylo

Code for uid-swapping.

*/

#include "includes.h"
RCSID("$Id: uidswap.c,v 1.10 1999/10/31 10:05:46 bg Exp $");

#include "ssh.h"
#include "uidswap.h"

/*
  temporarily_use_uid(uid)
  restore_uid()
  permanently_set_uid(uid)

  Note: all these functions must work in all of the following cases:

   1. euid=0, ruid=0
   2. euid=0, ruid!=0
   3. euid!=0, ruid!=0

   Additionally, they must work regardless of whether the system has
   POSIX saved uids or not. */

#if defined(HAVE_SETRESUID)
#define setreuid(ruid, euid) setresuid((ruid), (euid), -1)
#undef HAVE_SETREUID
#define HAVE_SETREUID
#endif

#ifdef __OpenBSD__
/* OpenBSD emulates setreuid(), use seteuid()! */
#undef HAVE_SETREUID
#endif

#ifdef HAVE_SETREUID
/* Saved effective uid. */
static uid_t saved_euid = 0;
static uid_t saved_ruid = 0;

/*
 * Temporarily changes to the given uid. If the effective user id
 * is not root, this does nothing. This call cannot be nested.
 */
void
temporarily_use_uid(uid_t uid)
{
  saved_euid = geteuid();
  saved_ruid = getuid();

  /* Set the effective uid to the given (unprivileged) uid.
   * Save effective uid as real uid so that uids can be restored later.*/
  if (setreuid(saved_euid, uid) == -1)
    fatal("setreuid(%d, %d): %.99s",
	  (int)saved_euid, (int)uid, strerror(errno));
  debug("temporarily_use_uid\tsetreuid(%d, %d): ok", (int)saved_euid,(int)uid);
}

/*
 * Restore real and effective uids back to the (privileged) saved uids.
 */
void
restore_uid()
{
  if (setreuid(saved_ruid, saved_euid) < 0)
    fatal("setreuid(%d, %d): %.99s",
	  (int)saved_ruid, (int)saved_euid, strerror(errno));
  debug("restore_uid\tsetreuid(%d, %d): ok", (int)saved_ruid, (int)saved_euid);
}

#else /* !HAVE_SETREUID */

/* Privileged uid is stored as real uid. */

void
temporarily_use_uid(uid_t uid)
{
  /* Propagate the privileged uid to all of our uids. */
  if (setuid(geteuid()) < 0)
    fatal("setuid %d: %.100s", (int)geteuid(), strerror(errno));

  /* Set the effective uid to the given (unprivileged) uid. */
  if (seteuid(uid) == -1)
    fatal("seteuid %d: %.100s", (int)uid, strerror(errno));
  debug("temporarily_use_uid\t(%d, %d): ok", getuid(), geteuid());
}

void
restore_uid()
{
  /* Propagate the privileged uid to all of our uids. */
  if (setuid(getuid()) < 0)
     fatal("setuid %d: %.100s", (int)getuid(), strerror(errno));
  debug("restore_uid\t(%d, %d): ok", getuid(), geteuid());
}
#endif /* !HAVE_SETREUID */

/*
 * Permanently sets all uids to the given uid.  This cannot be called
 * while temporarily_use_uid is effective.
 */
void
permanently_set_uid(uid_t uid)
{
#ifdef HAVE_SETRESUID
  if (setresuid(uid, uid, -1) < 0)
    fatal("setresuid(%d, %d, -1): %.99s", (int)uid, strerror(errno));
#else /* HAVE_SETRESUID */
  if (setuid(uid) < 0)
    fatal("setuid(%d): %.99s", (int)uid, strerror(errno));
#endif
  debug("permanently_set_uid\tsetuid(%d): ok", (int)uid);
}
