/*  -*- c -*-
 *
 * ----------------------------------------------------------------------
 * TRI's Simple Stream encryption system implementation
 * ----------------------------------------------------------------------
 * Created      : Fri Apr 14 14:20:00 1995 tri
 * Last modified: Wed Jul  5 01:35:18 1995 ylo
 * ----------------------------------------------------------------------
 * Copyright (c) 1995
 * Timo J. Rinne <tri@cirion.fi> and Cirion oy.
 * 
 * Address: Cirion oy, PO-BOX 250, 00121 HELSINKI, Finland
 * 
 * Even though this code is copyrighted property of the author, it can
 * still be used for non-commercial purposes under following conditions:
 * 
 *     1) This copyright notice is not removed.
 *     2) Source code follows any distribution of the software
 *        if possible.
 *     3) Copyright notice above is found in the documentation
 *        of the distributed software.
 * 
 * For possibility to use this source code for commercial product,
 * please contact address above.
 * 
 * Any express or implied warranties are disclaimed.  In no event
 * shall the author be liable for any damages caused (directly or
 * otherwise) by the use of this software.
 *
 * Permission granted to Mr. Tatu Ylonen <ylo@cs.hut.fi> to include this
 * code into SSH (Secure Shell).  Permission is granted to anyone to
 * use and distribute this code for any purpose as part of that product.
 * ----------------------------------------------------------------------
 */
#ifndef __TSS_H__
#define __TSS_H__ 1

/*
 * TSS_POOL_BYTES has to be 2^n and even multiple of 16.
 * 16k pool (0x4000) is standard and big enough.
 */
#define TSS_POOL_BYTES	0x4000
#define TSS_POOL_MASK	(TSS_POOL_BYTES - 1)
/*
 * TSS_SALT_BYTES has to be more than 0x10 but it should not be too big.
 * 0x20 is standard and OK.
 */
#define TSS_SALT_BYTES	0x20

struct tss_context {
    unsigned char key[TSS_POOL_BYTES];
    unsigned char salt[TSS_SALT_BYTES];
    int keyidx;
};

/*
 * Inits TSS context with given key.
 */
int TSS_Init(struct tss_context *context, 
	     const unsigned char *key, 
	     int keylen);

/*
 * Encrypts (decrypts) one data block within TSS context.
 */
int TSS_Encrypt(struct tss_context *context,
		unsigned char *data, 
		unsigned int len);
int TSS_Decrypt(struct tss_context *context,
		unsigned char *data,
		unsigned int len);

#endif /* not __TSS_H__ */

/* EOF (tss.h) */
