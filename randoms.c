/*

random.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar  4 14:55:57 1995 ylo

Cryptographically strong random number generation.

*/

/*
 * $Id: randoms.c,v 1.3 1995/08/29 22:22:50 ylo Exp $
 * $Log: randoms.c,v $
 * Revision 1.3  1995/08/29  22:22:50  ylo
 * 	Removed extra '&'.
 *
 * Revision 1.2  1995/07/13  01:29:20  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

#include "includes.h"
#include "randoms.h"

#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#ifdef HAVE_RUSAGE_H
#include <sys/rusage.h>
#endif /* HAVE_RUSAGE_H */
#endif /* HAVE_GETRUSAGE */

#ifdef HAVE_TIMES
#include <sys/times.h>
#endif /* HAVE_TIMES */

/* Initializes the random number generator, loads any random information
   from the given file, and acquires as much environmental noise as it
   can to initialize the random number generator.  More noise can be
   acquired later by calling random_add_noise + random_stir, or by
   calling random_get_environmental_noise again later when the environmental
   situation has changed. */

void random_initialize(RandomState *state, const char *filename)
{
  char buf[8192];
  int f, bytes;
  
  state->add_position = 0;
  state->next_available_byte = sizeof(state->stir_key);

  memset(state, 0, sizeof(state));
  
  /* Get noise from the file. */
  random_add_noise(state, filename, strlen(filename)); /* Use the path. */
  f = open(filename, O_RDONLY);
  if (f >= 0)
    {
      state->state[0] += f;
      bytes = read(f, buf, sizeof(buf));
      close(f);
      random_add_noise(state, buf, bytes);
      memset(buf, 0, sizeof(buf));
    }
  else
    { 
      /* Get all possible noise since we have no seed. */
      random_acquire_environmental_noise(state);
      random_save(state, filename);
    }

  /* Get noise from the address on stack and argument addresses. */
  state->state[0] ^= (unsigned long)state;
  state->state[1] ^= (unsigned long)buf;
  state->state[2] ^= (unsigned long)filename;
  state->state[3] ^= f;
  random_add_noise(state, filename, strlen(filename));

  /* Get easily available noise from the environment. */
  random_acquire_light_environmental_noise(state);
}

/* Acquires as much environmental noise as it can.  This is probably quite
   sufficient on a unix machine, but might be grossly inadequate on a
   single-user PC or a Macintosh. 

   We test the elapsed real time after each command, and abort if we have
   consumed over 30 seconds.  */

void random_acquire_environmental_noise(RandomState *state)
{
  time_t start_time;

  /* Record the start time. */
  start_time = time(NULL);

  /* Run these first so that other statistics accumulate from these.  We stop
     collecting more noise when we have spent 30 seconds real time; on a large
     system a single executed command is probably enough, whereas on small
     systems we must use all possible noise sources. */
  random_get_noise_from_command(state, "ps laxww 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "ps -al 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "ls -alni /tmp/. 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "w 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "netstat -s 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "netstat -an 2>/dev/null");
  if (time(NULL) - start_time < 30)
    random_get_noise_from_command(state, "netstat -in 2>/dev/null");

  /* Get other easily available noise. */
  random_acquire_light_environmental_noise(state);
}

/* Acquires easily available environmental noise. */

void random_acquire_light_environmental_noise(RandomState *state)
{
  state->state[((unsigned long)state >> 3) % 
	       (sizeof(state->state)/sizeof(state->state[0]))] += time(NULL);

#ifdef HAVE_GETTIMEOFDAY
  {
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    state->state[0] ^= tv.tv_sec;
    state->state[1] ^= tv.tv_usec;
    state->state[2] ^= tz.tz_minuteswest ^ (tz.tz_dsttime << 16);
#ifdef HAVE_CLOCK
    state->state[3] ^= clock();
#endif /* HAVE_CLOCK */
  }
#endif /* HAVE_GETTIMEOFDAY */
#ifdef HAVE_TIMES
  {
    struct tms tm;
    state->state[2] ^= times(&tm);
    state->state[4] ^= tm.tms_utime ^ (tm.tms_stime << 8) ^ 
      (tm.tms_cutime << 16) ^ (tm.tms_cstime << 24);
  }
#endif /* HAVE_TIMES */
#ifdef HAVE_GETRUSAGE
  {
    struct rusage ru, cru;
    getrusage(RUSAGE_SELF, &ru);
    getrusage(RUSAGE_CHILDREN, &cru);
    state->state[0] ^= ru.ru_utime.tv_usec + cru.ru_utime.tv_usec;
    state->state[2] ^= ru.ru_stime.tv_usec + cru.ru_stime.tv_usec;
    state->state[5] ^= ru.ru_maxrss + cru.ru_maxrss;
    state->state[6] ^= ru.ru_ixrss + cru.ru_ixrss;
    state->state[7] ^= ru.ru_idrss + cru.ru_idrss;
    state->state[8] ^= ru.ru_minflt + cru.ru_minflt;
    state->state[9] ^= ru.ru_majflt + cru.ru_majflt;
    state->state[10] ^= ru.ru_nswap + cru.ru_nswap;
    state->state[11] ^= ru.ru_inblock + cru.ru_inblock;
    state->state[12] ^= ru.ru_oublock + cru.ru_oublock;
    state->state[13] ^= (ru.ru_msgsnd ^ ru.ru_msgrcv ^ ru.ru_nsignals) +
      (cru.ru_msgsnd ^ cru.ru_msgrcv ^ cru.ru_nsignals);
    state->state[14] ^= ru.ru_nvcsw + cru.ru_nvcsw;
    state->state[15] ^= ru.ru_nivcsw + cru.ru_nivcsw;
  }
#endif /* HAVE_GETRUSAGE */
  state->state[11] += getpid();
  state->state[12] += getppid();
  state->state[10] += getuid();
  state->state[10] += (getgid() << 16);
#ifdef _POSIX_CHILD_MAX
  state->state[13] ^= _POSIX_CHILD_MAX << 16;
#endif /* _POSIX_CHILD_MAX */
#ifdef CLK_TCK
  state->state[14] ^= CLK_TCK << 16;
#endif /* CLK_TCK */

  random_stir(state);
}

/* Executes the given command, and processes its output as noise. */

void random_get_noise_from_command(RandomState *state, const char *cmd)
{
#ifdef HAVE_POPEN
  char line[1000];
  FILE *f;

  f = popen(cmd, "r");
  if (!f)
    return;
  while (fgets(line, sizeof(line), f))
    random_add_noise(state, line, strlen(line));
  pclose(f);
  memset(line, 0, sizeof(line));
#endif /* HAVE_POPEN */
}

/* Adds the contents of the buffer as noise. */

void random_add_noise(RandomState *state, const void *buf, unsigned int bytes)
{
  unsigned int pos = state->add_position;
  const char *input = buf;
  char *s = (char *)&state->state[0];
  while (bytes > 0)
    {
      if (pos >= RANDOM_STATE_BYTES)
	{
	  pos = 0;
	  random_stir(state);
	}
      s[pos] ^= *input;
      input++;
      bytes--;
      pos++;
    }
  state->add_position = pos;
}

/* Stirs the random pool to consume any newly acquired noise or to get more
   random numbers.

   This works by encrypting the data in the buffer in CFB mode with MD5 as
   the cipher. */

void random_stir(RandomState *state)
{
  uint32 iv[4];
  unsigned int i;

  /* Start IV from last block of random pool. */
  memcpy(iv, &state->state[RANDOM_STATE_WORDS - 4], sizeof(iv));

  /* First CFB pass. */
  for (i = 0; i < RANDOM_STATE_WORDS; i += 4)
    {
      MD5Transform(iv, state->stir_key);
      iv[0] = state->state[i] ^= iv[0];
      iv[1] = state->state[i + 1] ^= iv[1];
      iv[2] = state->state[i + 2] ^= iv[2];
      iv[3] = state->state[i + 3] ^= iv[3];
    }

  /* Get new key. */
  memcpy(state->stir_key, state->state, sizeof(state->stir_key));

  /* Second CFB pass. */
  for (i = 0; i < RANDOM_STATE_WORDS; i += 4)
    {
      MD5Transform(iv, state->stir_key);
      iv[0] = state->state[i] ^= iv[0];
      iv[1] = state->state[i + 1] ^= iv[1];
      iv[2] = state->state[i + 2] ^= iv[2];
      iv[3] = state->state[i + 3] ^= iv[3];
    }
  
  memset(iv, 0, sizeof(iv));

  state->add_position = 0;

  /* Some data in the beginning is not returned to aboid giving an observer
     complete knowledge of the contents of our random pool. */
  state->next_available_byte = sizeof(state->stir_key);
}

/* Returns a random byte.  Stirs the random pool if necessary.  Acquires
   new environmental noise approximately every five minutes. */

unsigned int random_get_byte(RandomState *state)
{
  if (state->next_available_byte >= RANDOM_STATE_BYTES)
    {
      /* Get some easily available noise.  More importantly, this stirs
	 the pool. */
      random_acquire_light_environmental_noise(state);
    }
  assert(state->next_available_byte < RANDOM_STATE_BYTES);
  return ((unsigned char *)state->state)[state->next_available_byte++];
}

/* Saves random data in a disk file.  This is used to create a file that
   can be used as a random seed on future runs.  Only half of the random
   data in our pool is written to the file to avoid an observer being
   able to deduce the contents of our random pool from the file. */

void random_save(RandomState *state, const char *filename)
{
  char buf[RANDOM_STATE_BYTES / 2];  /* Save only half of its bits. */
  int i, f;

  /* Get some environmental noise to make it harder to predict previous
     values from saved bits (besides, we have now probably consumed some
     resources so the noise may be really useful).  This also stirs
     the pool. */
  random_acquire_light_environmental_noise(state);

  /* Get as many bytes as is half the size of the pool.  I am assuming
     this will get enough randomness for it to be very useful, but will
     not reveal enough to make it possible to determine previous or future
     returns by the generator. */
  for (i = 0; i < sizeof(buf); i++)
    buf[i] = random_get_byte(state);

  /* Again get a little noise and stir it to mix the unrevealed half with 
     those bits that have been saved to a file.  There should be enough 
     unrevealed bits (plus the new noise) to make it infeasible to try to 
     guess future values from the saved bits. */
  random_acquire_light_environmental_noise(state);

  /* Create and write the file.  Failure to create the file is silently
     ignored. */
  f = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  if (f >= 0)
    {
      /* Creation successful.  Write data to the file. */
      write(f, buf, sizeof(buf));
      close(f);
    }
  memset(buf, 0, sizeof(buf));
}

/* Clears the random number generator data structures. */

void random_clear(RandomState *state)
{
  memset(state, 0, sizeof(*state));
}
