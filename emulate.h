#ifndef EMULATE_H
#define EMULATE_H

#define EMULATE_OLD_CHANNEL_CODE 0x0001

#define EMULATE_MAJOR_VERSION_MISMATCH 1
#define EMULATE_VERSION_TOO_OLD 2
#define EMULATE_VERSION_REALLY_TOO_OLD 3
#define EMULATE_VERSION_TOO_NEW 4

extern unsigned long emulation_information;

extern int check_emulation(int her_major_version,
			    int her_minor_version,
			    int *return_major,
			    int *return_minor);

#endif /* EMULATE_H */

