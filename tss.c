/*  -*- c -*-
 *
 * ----------------------------------------------------------------------
 * TRI's Simple Stream encryption system implementation
 * ----------------------------------------------------------------------
 * Created      : Fri Apr 14 14:20:00 1995 tri
 * Last modified: Wed Jul 12 21:58:55 1995 ylo
 * ----------------------------------------------------------------------
 * Copyright (c) 1995
 * Timo J. Rinne <tri@iki.fi> and Cirion oy.
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
#define __TSS_C__ 1

#include "includes.h"
#include "md5.h"
#include "ssh.h"
#include "tss.h"

int TSS_Init(struct tss_context *context,
	     const unsigned char *key, 
	     int keylen)
{
    int i;
    struct MD5Context mdctx;

    if((!context) || (!key) || (keylen <= 0))
	return 0;
    context->keyidx = 0;
    (context->key)[0] = (unsigned char)(keylen & 0xff);
    (context->key)[1] = (unsigned char)((keylen >> 8) & 0xff);
    for(i = 2; i < sizeof(context->key); i++) 
        (context->key)[i] = key[i % keylen];
    for(i = 0; i <= 16; i++) { 
	MD5Init(&mdctx);
	MD5Update(&mdctx, context->key, (i + 1) * 16);
	MD5Final(&((context->key)[i * 16]), &mdctx);
    }
    for(i = 0; i < sizeof(context->key); i++) {
	(context->key)[(i + 1) & TSS_POOL_MASK] ^= (context->key)[i];
	(context->key)[(i + 2 + ((context->key)[i])) & TSS_POOL_MASK] ^= 
	    ((context->key)[i] << 6) | 
	    ((context->key)[(i + 1) & TSS_POOL_MASK] >> 2);
    }
    (context->salt)[0] = (unsigned char)(keylen & 0xff);
    (context->salt)[1] = (unsigned char)((keylen >> 8) & 0xff);
    for(i = 2; i < sizeof(context->salt); i++) 
        (context->salt)[i] = key[i % keylen];
    return 1;
}

static void TSS_Resalt(struct tss_context *context)
{
    int i;
    struct MD5Context mdctx;

    MD5Init(&mdctx);
    MD5Update(&mdctx, context->salt, sizeof(context->salt));
    MD5Update(&mdctx, &((context->key)[sizeof(context->key) - 16]), 16);
    MD5Final(context->salt, &mdctx);
    for(i = 0; i < 16; i++)
	(context->key)[i] ^= (context->salt)[i];
    return;
}

int TSS_Encrypt(struct tss_context *context,
		unsigned char *data,
		unsigned int len)
{
    unsigned int i;

    for(i = 0; i < len; i++) {
	if(!(context->keyidx = ((context->keyidx + 1) & TSS_POOL_MASK)))
	    TSS_Resalt(context);
	(context->key)[(context->keyidx + 1) & TSS_POOL_MASK] ^= data[i];
	(context->key)[(context->keyidx + 3) & TSS_POOL_MASK] ^= 
	    (data[i] << 6) | (data[i] >> 2);
	data[i] ^= (context->key)[context->keyidx];
	(context->key)[(context->keyidx + 2) & TSS_POOL_MASK] ^= data[i];
	(context->key)[(context->keyidx + 4) & TSS_POOL_MASK] ^= 
	    (data[i] << 3) | (data[i] >> 5);
    }
    return 1;
}

int TSS_Decrypt(struct tss_context *context, 
		unsigned char *data,
		unsigned int len)
{
    unsigned int i;

    for(i = 0; i < len; i++) {
	if(!(context->keyidx = ((context->keyidx + 1) & TSS_POOL_MASK)))
	    TSS_Resalt(context);
	(context->key)[(context->keyidx + 2) & TSS_POOL_MASK] ^= data[i];
	(context->key)[(context->keyidx + 4) & TSS_POOL_MASK] ^= 
	    (data[i] << 3) | (data[i] >> 5);
	data[i] ^= (context->key)[context->keyidx];
	(context->key)[(context->keyidx + 1) & TSS_POOL_MASK] ^= data[i];
	(context->key)[(context->keyidx + 3) & TSS_POOL_MASK] ^= 
	    (data[i] << 6) | (data[i] >> 2);
    }
    return 1;
}

/* EOF (tss.c) */
