/*

sshsia.h

Author: Tom Woodburn <woodburn@zk3.dec.com>

Helper functions for using the SIA (Security Integration Architecture)
functions of Tru64 UNIX.

Copyright (c) 1999 COMPAQ Computer Corp, all rights reserved
Copyright (c) 1999 SSH Communications Security Oy, Espoo, Finland

*/

#ifndef SSHSIA_H
#define SSHSIA_H

#include <sia.h>

void ssh_sia_initialize(int ac, char **av);
void ssh_sia_get_args(int *ac, char ***av);
int ssh_sia_validate_user(sia_collect_func_t *collect, int argc, char *argv[],
                         char *hostname, char *username, char *tty,
                         int colinput, char *gssapi, char *passphrase);
int ssh_sia_no_password(const char *server_user);

#endif /* SSHSIA_H */
