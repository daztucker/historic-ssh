
#include "includes.h"
RCSID("$Id: fingerprint.c,v 1.2 1999/11/07 14:48:13 bg Exp $");

#include "xmalloc.h"
#include "ssh.h"

static
char *
mpz_to_bin(char *buffer, MP_INT *value)
{
  int bits = mpz_sizeinbase(value, 2);
  int hex_size = mpz_sizeinbase(value, 16);
  char *buf = xmalloc(hex_size + 2);
  int i, oi, byte;
  
  /* Get the value of the number in hex.  Too bad that gmp does not allow
     us to get it in binary. */
  mpz_get_str(buf, 16, value);

  /* i is "input index", oi is "output index".  Both point to the same array,
     and start from the beginning.  "input index" moves twice as fast. */
  i = 0;
  oi = 0;
  /* Check for an odd number of hex digits.  Process the odd digit 
     separately. */
  if (hex_size & 1)
    {
      sscanf(buf, "%1x", &byte);
      buf[oi++] = byte;
      i = 1;
    }

  /* Convert the hex number into binary representation. */
  for (; i < hex_size; i += 2)
    {
      sscanf(buf + i, "%2x", &byte);
      buf[oi++] = byte;
    }
  
  assert(oi == ((bits + 7) / 8));
  
  /* Store the binary data. */
  memcpy(buffer, buf, oi);
  buffer = buffer + oi;		/* Next free byte */
  /* Clear the temporary data. */
  memset(buf, 0, hex_size);
  xfree(buf);
  return buffer;
}

/* Generate key fingerprint in ascii format. */
char *
fingerprint(RSAPublicKey *key)
{
  static char retval[80];

  struct MD5Context c;
  unsigned char d[16];

  int len = ((mpz_sizeinbase(&key->n, 2) + 7)/8
	     + (mpz_sizeinbase(&key->e, 2) + 7)/8);
  char *buf = xmalloc(len);
  char *t = buf;

  t = mpz_to_bin(t, &key->n);
  mpz_to_bin(t, &key->e);

  MD5Init(&c);
  MD5Update(&c, buf, len);
  MD5Final(d, &c);
  sprintf(retval,
	  "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
	  d[0], d[1],  d[2],  d[3],  d[4],  d[5],  d[6],  d[7],
	  d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
  memset(buf, 0, len);
  xfree(buf);
  return retval;
}
