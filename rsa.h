/*

rsa.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Mar  3 22:01:06 1995 ylo

RSA key generation, encryption and decryption.

*/

/* RCSID("$Id: rsa.h,v 1.6 1999/11/09 19:55:53 bg Exp $"); */

#ifndef RSA_H
#define RSA_H

#include "gmp.h"
#include "randoms.h"

typedef MP_INT BIGNUM;

typedef struct
{
  unsigned int bits;		/* Modulus size in bits. */
  BIGNUM n;			/* Modulus. */
  BIGNUM e;			/* Public exponent. */
} RSAPublicKey;

typedef struct
{
  unsigned int bits;		/* Modulus size in bits. */
  BIGNUM n;			/* Modulus. */
  BIGNUM e;			/* Public exponent. */
  BIGNUM d;			/* Private exponent. */
  BIGNUM u;			/* Multiplicative inverse of p mod q. */
  BIGNUM p;			/* Prime number p. */
  BIGNUM q;			/* Prime number q. */
} RSAPrivateKey;

typedef RSAPrivateKey RSA;

/* Generates a random integer of the desired number of bits. */
void rsa_random_integer(BIGNUM *ret, RandomState *state, unsigned int bits);

/* Makes and returns a random prime of the desired number of bits.
   Note that the random number generator must be initialized properly
   before using this.

   The generated prime will have the highest bit set, and will have
   the two lowest bits set. */
void rsa_random_prime(BIGNUM *ret, RandomState *state, unsigned int bits);

/* Generates RSA public and private keys.  This initializes the data
   structures; they should be freed with rsa_clear_private_key and
   rsa_clear_public_key. */
void rsa_generate_key(RSA *prv, RSAPublicKey *pub, 
		      RandomState *state, unsigned int bits);

/* Frees any memory associated with the private key. */
void rsa_clear_private_key(RSA *prv);

/* Frees any memory associated with the public key. */
void rsa_clear_public_key(RSAPublicKey *pub);

/* Performs a private-key RSA operation (encrypt/decrypt). */
void rsa_private(BIGNUM *output, BIGNUM *input, RSA *prv);

/* Performs a public-key RSA operation (encrypt/decrypt). */
void rsa_public(BIGNUM *output, BIGNUM *input, RSAPublicKey *pub);

/* Sets BIGNUM memory allocation routines to ones that clear any memory
   when freed. */
void rsa_set_mp_memory_allocation();

/* Indicates whether the rsa module is permitted to show messages on
   the terminal. */
void rsa_set_verbose(int verbose);

/************* Kludge functions for RSAREF compatibility *******************/

/* These functions are a kludge but can be implemented using rsaref. */

/* Encrypt input using the public key.  The 24 least significant bits of
   input must contain the value 0x000200. */
void rsa_public_encrypt(BIGNUM *output, BIGNUM *input, RSAPublicKey *key,
			RandomState *state);

/* Decrypt input using the private key.  The 24 least significant bits of
   the result must contain the value 0x000200. */
void rsa_private_decrypt(BIGNUM *output, BIGNUM *input, RSA *key);

/* Generate key fingerprint in ascii format. */
char *fingerprint(RSAPublicKey *key);

#endif /* RSA_H */
