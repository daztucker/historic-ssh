#include "includes.h"
RCSID("$Id: compat.c,v 1.1 1999/10/20 19:54:31 bg Exp $");

#include "ssh.h"

int compat13=0;
void enable_compat13(void){
	log("Enabling compatibility mode for protocol 1.3");
	compat13=1;
}
