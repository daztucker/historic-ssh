/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "includes.h"
RCSID("$Id: ssh-fingerprint.c,v 1.3 1999/11/09 19:53:31 bg Exp $");

#include "xmalloc.h"
#include "ssh.h"

int
print_identity_file(const char *filename)
{
  FILE *f;

  /* Read data from the file into the buffer. */
  f = fopen(filename, "r");
  if (f == NULL)
    return 0;

  /* Line format is bits e n identity */
  while (!feof(f))
    {
      int c;
      char identity[128];
      RSAPublicKey pub;

      fscanf(f, "%ud ", &pub.bits);
      mpz_init(&pub.e);
      mpz_inp_str(&pub.e, f, 10);
      mpz_init(&pub.n);
      mpz_inp_str(&pub.n, f, 10);
      pub.bits = mpz_sizeinbase(&pub.n, 2);
      fscanf(f, " %s", identity);
      printf("%s %4d %s\n", fingerprint(&pub), pub.bits, identity);
      mpz_clear(&pub.e);
      mpz_clear(&pub.n);

      for (c = getc(f); c != EOF && c != '\n'; c = getc(f))
	;
      c = getc(f);
      if (c != EOF)
	ungetc(c, f);
    }
  fclose(f);
  
  return 1;
}

int
print_known_hosts_file(const char *filename)
{
  FILE *f;
  int linenum = 0;

  /* Read data from the file into the buffer. */
  f = fopen(filename, "r");
  if (f == NULL)
    return 0;

  /* Per line format is hostname bits e n */
  while (!feof(f))
    {
      int c;
      char host[128];
      RSAPublicKey pub;

      linenum++;
      fscanf(f, "%s ", host);
      fscanf(f, "%ud ", &pub.bits);
      mpz_init(&pub.e);
      mpz_inp_str(&pub.e, f, 10);
      mpz_init(&pub.n);
      mpz_inp_str(&pub.n, f, 10);
      pub.bits = mpz_sizeinbase(&pub.n, 2);
      printf("%s %4d root@%s\n", fingerprint(&pub), pub.bits, host);
      mpz_clear(&pub.e);
      mpz_clear(&pub.n);

      for (c = getc(f); c != EOF && c != '\n'; c = getc(f))
	;
      c = getc(f);
      if (c != EOF)
	ungetc(c, f);
    }
  fclose(f);
  
  return 1;
}

static char *pname;

void
usage()
{
  fprintf(stderr, "Usage: %s [-us] [-i identity_file] [-k host_key_file]\n",
	  pname);
  fprintf(stderr,
	  "\nPrint public key fingerprints from host or identity files:\n");
  fprintf(stderr, "\t -s\tPrint systems keys\n");
  fprintf(stderr, "\t -u\tPrint user keys\n");
  fprintf(stderr, "\t -i\tPrint identity file (usually ends with .pub).\n");
  fprintf(stderr, "\t -k\tPrint known_hosts file.\n");
  exit(1);
}

int
main(int argc, char **argv)
{
  char ch;
  char *host_file = 0;
  char *identity_file = 0;
  int uopt = 0;
  int ex = 0;

  pname = argv[0];

  /* Set RSA (actually gmp) memory allocation functions. */
  rsa_set_mp_memory_allocation();

  while ((ch = getopt(argc, argv, "hi:k:us")) != -1)
    switch (ch) {
    case 'h':
      usage();
      break;
    case 'i':
      identity_file = optarg;
      break;
    case 'k':
      host_file = optarg;
      break;
    case 'u':
      uopt = 1;
      break;
    case 's':
      identity_file = HOST_KEY_FILE".pub";
      host_file = SSH_SYSTEM_HOSTFILE;
      break;
    default:
      usage();
      break;
    }
  argc -= optind;
  argv += optind;

  if (argc != 0)
    usage();

  if (uopt)
    {
      struct passwd *pw = getpwuid(getuid());
      if (pw == 0)
	fatal("You don't exist, go away!");
      identity_file = xmalloc(1000);
      sprintf(identity_file, "%.100s/%.100s%.100s",
	      pw->pw_dir, SSH_CLIENT_IDENTITY, ".pub");
      host_file = xmalloc(1000);
      sprintf(host_file, "%.100s/%.100s", pw->pw_dir, ".ssh/known_hosts");
    }

  if (identity_file == 0 && host_file == 0)
    identity_file = HOST_KEY_FILE".pub";

  if (identity_file)
    if (!print_identity_file(identity_file))
      {
	fprintf(stderr, "%s: Warning, can't open %s\n", pname, identity_file);
	ex = 1;
      }

  if (host_file)
    if (!print_known_hosts_file(host_file))
      {
	fprintf(stderr, "%s: Warning can't open %s\n", pname, host_file);
	ex = 1;
      }

  exit(ex);
}

void
fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(255);
}
