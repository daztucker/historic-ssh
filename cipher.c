/*

cipher.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Apr 19 17:41:39 1995 ylo
Last modified: Wed Jul 12 00:22:48 1995 ylo

*/

#include "includes.h"
#include "ssh.h"
#include "cipher.h"

/* Names of all encryption algorithms.  These must match the numbers defined
   int cipher.h. */
static char *cipher_names[] =
{ "none", "idea", "des", "3des", "tss", "rc4" };

/* Returns a bit mask indicating which ciphers are supported by this
   implementation.  The bit mask has the corresponding bit set of each
   supported cipher. */

unsigned int cipher_mask()
{
  unsigned int mask = 0;
  mask |= 1 << SSH_CIPHER_NONE;
  mask |= 1 << SSH_CIPHER_IDEA;
  mask |= 1 << SSH_CIPHER_DES;
  mask |= 1 << SSH_CIPHER_3DES;
  mask |= 1 << SSH_CIPHER_TSS;
  mask |= 1 << SSH_CIPHER_RC4;
  return mask;
}

/* Returns the name of the cipher. */

const char *cipher_name(int cipher)
{
  if (cipher < 0 || cipher >= sizeof(cipher_names) / sizeof(cipher_names[0]))
    fatal("cipher_name: bad cipher number: %d", cipher);
  return cipher_names[cipher];
}

/* Parses the name of the cipher.  Returns the number of the corresponding
   cipher, or -1 on error. */

int cipher_number(const char *name)
{
  int i;
  for (i = 0; i < sizeof(cipher_names) / sizeof(cipher_names[0]); i++)
    if (strcmp(cipher_names[i], name) == 0)
      return i;
  return -1;
}

/* Selects the cipher, and keys if by computing the MD5 checksum of the
   passphrase and using the resulting 16 bytes as the key. */

void cipher_set_key_string(CipherContext *context, int cipher,
			   const char *passphrase, int for_encryption)
{
  struct MD5Context md;
  unsigned char digest[16];
  
  MD5Init(&md);
  MD5Update(&md, (const unsigned char *)passphrase, strlen(passphrase));
  MD5Final(digest, &md);

  cipher_set_key(context, cipher, digest, 16, for_encryption);
  
  memset(digest, 0, sizeof(digest));
  memset(&md, 0, sizeof(md));
}

/* Selects the cipher to use and sets the key. */

void cipher_set_key(CipherContext *context, int cipher,
		    const unsigned char *key, int keylen, int for_encryption)
{
  unsigned char padded[32];

  /* Set cipher type. */
  context->type = cipher;

  /* Get 32 bytes of key data.  Pad if necessary.  (So that code below does
     not need to worry about key size). */
  memset(padded, 0, sizeof(padded));
  memcpy(padded, key, keylen < sizeof(padded) ? keylen : sizeof(padded));

  /* Initialize the initialization vector. */
  switch (cipher)
    {
    case SSH_CIPHER_NONE:
      break;

    case SSH_CIPHER_IDEA:
      if (keylen < 16)
	error("Key length %d is insufficient for IDEA.", keylen);
      idea_set_key(&context->u.idea.key, padded);
      memset(context->u.idea.iv, 0, sizeof(context->u.idea.iv));
      break;

    case SSH_CIPHER_DES:
      /* Note: the least significant bit of each byte of key is parity, 
	 and must be ignored by the implementation.  8 bytes of key are
	 used. */
      if (keylen < 8)
	error("Key length %d is insufficient for DES.", keylen);
      des_set_key(padded, &context->u.des.key);
      memset(context->u.des.iv, 0, sizeof(context->u.des.iv));
      break;

    case SSH_CIPHER_3DES:
      /* Note: the least significant bit of each byte of key is parity, 
	 and must be ignored by the implementation.  16 bytes of key are
	 used (first and last keys are the same). */
      if (keylen < 16)
	error("Key length %d is insufficient for 3DES.", keylen);
      des_set_key(padded, &context->u.des3.key1);
      des_set_key(padded + 8, &context->u.des3.key2);
      des_set_key(padded + 16, &context->u.des3.key3);
      memset(context->u.des3.iv1, 0, sizeof(context->u.des3.iv1));
      memset(context->u.des3.iv2, 0, sizeof(context->u.des3.iv2));
      memset(context->u.des3.iv3, 0, sizeof(context->u.des3.iv3));
      break;

    case SSH_CIPHER_TSS:
      if (keylen < 8)
	error("Key length %d is insufficient for TSS.", keylen);
      TSS_Init(&context->u.tss, key, keylen);
      break;

    case SSH_CIPHER_RC4:
      rc4_init(&context->u.rc4, key, keylen);
      break;

    default:
      fatal("cipher_set_key: unknown cipher: %d", cipher);
    }
  memset(padded, 0, sizeof(padded));
}

/* Encrypts data using the cipher. */

void cipher_encrypt(CipherContext *context, unsigned char *dest,
		    const unsigned char *src, unsigned int len)
{
  switch (context->type)
    {
    case SSH_CIPHER_NONE:
      memcpy(dest, src, len);
      break;

    case SSH_CIPHER_IDEA:
      idea_cfb_encrypt(&context->u.idea.key, context->u.idea.iv, 
		       dest, src, len);
      break;

    case SSH_CIPHER_DES:
      des_cbc_encrypt(&context->u.des.key, context->u.des.iv, dest, src, len);
      break;

    case SSH_CIPHER_3DES:
      des_3cbc_encrypt(&context->u.des3.key1, context->u.des3.iv1,
		       &context->u.des3.key2, context->u.des3.iv2,
		       &context->u.des3.key3, context->u.des3.iv3,
		       dest, src, len);
      break;

    case SSH_CIPHER_TSS:
      memcpy(dest, src, len);
      TSS_Encrypt(&context->u.tss, dest, len);
      break;

    case SSH_CIPHER_RC4:
      rc4_encrypt(&context->u.rc4, dest, src, len);
      break;

    default:
      fatal("cipher_encrypt: unknown cipher: %d", context->type);
    }
}
  
/* Decrypts data using the cipher. */

void cipher_decrypt(CipherContext *context, unsigned char *dest,
		    const unsigned char *src, unsigned int len)
{
  switch (context->type)
    {
    case SSH_CIPHER_NONE:
      memcpy(dest, src, len);
      break;

    case SSH_CIPHER_IDEA:
      idea_cfb_decrypt(&context->u.idea.key, context->u.idea.iv, 
		       dest, src, len);
      break;

    case SSH_CIPHER_DES:
      des_cbc_decrypt(&context->u.des.key, context->u.des.iv, dest, src, len);
      break;

    case SSH_CIPHER_3DES:
      des_3cbc_decrypt(&context->u.des3.key1, context->u.des3.iv1,
		       &context->u.des3.key2, context->u.des3.iv2,
		       &context->u.des3.key3, context->u.des3.iv3,
		       dest, src, len);
      break;

    case SSH_CIPHER_TSS:
      memcpy(dest, src, len);
      TSS_Decrypt(&context->u.tss, dest, len);
      break;

    case SSH_CIPHER_RC4:
      rc4_decrypt(&context->u.rc4, dest, src, len);
      break;

    default:
      fatal("cipher_decrypt: unknown cipher: %d", context->type);
    }
}
