# Reconstructed history of OpenSSH, OSSH and original SSH.

This repository is a partial reconstruction of the change history of
Tatu Ylönen's original ssh version 1 and Björn Grönvall's OSSH
onto which the current OpenSSH Portable's git repository has been
grafted and rebased.  This allows attribution of code present in modern
OpenSSH back to its origin in those two products.

There are 4 branches:

 - ssh - Tatu's original ssh.  Included dependencies (eg GMP, zlib) are ignored.
 - ossh - Björn's OSSH which is branched off ssh-1.2.12.
 - openbsd - Initial import into OpenBSD, forked from ossh-1.2.16
 - openssh - Modern Portable OpenSSH, forked from openbsd
 - default - OpenSSH plus this README.md

The ssh1 and OSSH history was reconstructed from the
publically released tarballs and the history as described at
https://www.openssh.com/history.html.  Where possible (eg from embedded
CVS changelogs within source files) changes have been attributed to the
responsible individual however that was not always possible.  In the
ssh branch, if attribution could not be determined, it is assumed Tatu
is the author.  Other than the initial import, the 'openbsd' branch is
currently not populated.

OpenSSH was committed to OpenBSD at Sep 26 20:53:38 1999 UTC.  The OSSH
1.2.16 tarball is timestamped 17 Aug 1999 and 1.5.1 is timestamped Nov 14
1999 so OSSH 1.2.16 is the version most likely to have been the source
for OpenSSH (the initial commit message mentions "ssh-1.2.16" which may
actually be referring to the ossh version).  Regardless, it's the only
one in the correct time range available anyway).

If more data becomes available I reserve the right to regenerate this
repo which will necessarily change the commit IDs, so don't rely on them.

I was not able to locate ssh versions 1.2.1-1.2.5 and 1.2.7-1.2.9
Based on the version numbers, I suspect there were ossh versions 1.2.13,
1.2.14, 1.2.15, 1.5.8, 1.5.9 and 1.5.10 but I have not been able to locate
them.  If anyone has them (or proper revision history for either project)
I'd be interested in adding them so please let me know.

  - Darren Tucker (dtucker at dtucker dot net).
