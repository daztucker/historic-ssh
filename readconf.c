/*

readconf.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Apr 22 00:03:10 1995 ylo

Functions for reading the configuration files.

*/

/*
 * $Id: readconf.c,v 1.6 1995/09/09 21:26:44 ylo Exp $
 * $Log: readconf.c,v $
 * Revision 1.6  1995/09/09  21:26:44  ylo
 * /m/shadows/u2/users/ylo/ssh/README
 *
 * Revision 1.5  1995/09/06  19:52:36  ylo
 * 	Fixed spelling of fascist.
 *
 * Revision 1.4  1995/08/21  23:25:55  ylo
 * 	Minor cleanup.
 *
 * Revision 1.3  1995/07/27  00:39:00  ylo
 * 	Added GlobalKnownHostsFile and UserKnownHostsFile.
 *
 * Revision 1.2  1995/07/13  01:30:39  ylo
 * 	Removed "Last modified" header.
 * 	Added cvs log.
 *
 * $Endlog$
 */

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     FallBackToRsh no

   Host fake.com
     HostName another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Cipher 3des

   Host fascist.blob.com
     Port 23123
     User tylonen
     RhostsAuthentication no
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p

   Host *.fr
     UseRsh yes

   Host *.su
     Cipher none
     PasswordAuthentication no

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 yes
     RhostsAuthentication yes
     PasswordAuthentication yes
     RSAAuthentication yes
     RhostsRSAAuthentication yes
     FallBackToRsh no
     UseRsh no
     IdentityFile ~/.ssh/identity
     Port 22
     Cipher idea
     EscapeChar ~

*/

#include "includes.h"
#include "ssh.h"
#include "cipher.h"
#include "readconf.h"
#include "xmalloc.h"

/* Keyword tokens. */

typedef enum
{
  oForwardAgent, oForwardX11, oRhostsAuthentication,
  oPasswordAuthentication, oRSAAuthentication, oFallBackToRsh, oUseRsh,
  oIdentityFile, oHostName, oPort, oCipher, oRemoteForward, oLocalForward, 
  oUser, oHost, oEscapeChar, oRhostsRSAAuthentication,
  oGlobalKnownHostsFile, oUserKnownHostsFile
} OpCodes;

/* Textual representations of the tokens. */

static struct
{
  const char *name;
  OpCodes opcode;
} keywords[] =
{
  { "ForwardAgent", oForwardAgent },
  { "ForwardX11", oForwardX11 },
  { "RhostsAuthentication", oRhostsAuthentication },
  { "PasswordAuthentication", oPasswordAuthentication },
  { "RSAAuthentication", oRSAAuthentication },
  { "FallBackToRsh", oFallBackToRsh },
  { "UseRsh", oUseRsh },
  { "IdentityFile", oIdentityFile },
  { "HostName", oHostName },
  { "Port", oPort },
  { "Cipher", oCipher },
  { "RemoteForward", oRemoteForward },
  { "LocalForward", oLocalForward },
  { "User", oUser },
  { "Host", oHost },
  { "EscapeChar", oEscapeChar },
  { "RhostsRSAAuthentication", oRhostsRSAAuthentication },
  { "GlobalKnownHostsFile", oGlobalKnownHostsFile },
  { "UserKnownHostsFile", oUserKnownHostsFile },
  { NULL, 0 }
};

/* Characters considered whitespace in strtok calls. */
#define WHITESPACE " \t\r\n"


/* Adds a local TCP/IP port forward to options.  Never returns if there
   is an error. */

void add_local_forward(Options *options, int port, const char *host,
		       int host_port)
{
  Forward *fwd;
  if (options->num_local_forwards >= SSH_MAX_FORWARDS_PER_DIRECTION)
    fatal("Too many local forwards (max %d).", SSH_MAX_FORWARDS_PER_DIRECTION);
  fwd = &options->local_forwards[options->num_local_forwards++];
  fwd->port = port;
  fwd->host = xstrdup(host);
  fwd->host_port = host_port;
}

/* Adds a remote TCP/IP port forward to options.  Never returns if there
   is an error. */

void add_remote_forward(Options *options, int port, const char *host,
		       int host_port)
{
  Forward *fwd;
  if (options->num_remote_forwards >= SSH_MAX_FORWARDS_PER_DIRECTION)
    fatal("Too many remote forwards (max %d).", 
	  SSH_MAX_FORWARDS_PER_DIRECTION);
  fwd = &options->remote_forwards[options->num_remote_forwards++];
  fwd->port = port;
  fwd->host = xstrdup(host);
  fwd->host_port = host_port;
}

/* Returns the number of the token pointed to by cp of length len.
   Never returns if the token is not known. */

static OpCodes parse_token(const char *cp, const char *filename, int linenum)
{
  unsigned int i;

  for (i = 0; keywords[i].name; i++)
    if (strcmp(cp, keywords[i].name) == 0)
      return keywords[i].opcode;

  fatal("%.200s line %d: Bad configuration option.",
	filename, linenum);
  /*NOTREACHED*/
  return 0;
}

/* Processes a single option line as used in the configuration files.
   This only sets those values that have not already been set. */

void process_config_line(Options *options, const char *host,
			 char *line, const char *filename, int linenum,
			 int *activep)
{
  char buf[256], *cp, **charptr;
  int opcode, *intptr, value, fwd_port, fwd_host_port;

  /* Skip leading whitespace. */
  cp = line + strspn(line, WHITESPACE);
  if (!*cp || *cp == '\n' || *cp == '#')
    return;

  /* Get the keyword. (Each line is supposed to begin with a keyword). */
  cp = strtok(cp, WHITESPACE);
  opcode = parse_token(cp, filename, linenum);

  switch (opcode)
    {

    case oForwardAgent:
      intptr = &options->forward_agent;
    parse_flag:
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing yes/no argument.",
	      filename, linenum);
      value = 0; /* To avoid compiler warning... */
      if (strcmp(cp, "yes") == 0)
	value = 1;
      else
	if (strcmp(cp, "no") == 0)
	  value = 0;
	else
	  fatal("%.200s line %d: Bad yes/no argument.", 
		filename, linenum);
      if (*activep && *intptr == -1)
	*intptr = value;
      break;
      
    case oForwardX11:
      intptr = &options->forward_x11;
      goto parse_flag;
      
    case oRhostsAuthentication:
      intptr = &options->rhosts_authentication;
      goto parse_flag;
      
    case oPasswordAuthentication:
      intptr = &options->password_authentication;
      goto parse_flag;
      
    case oRSAAuthentication:
      intptr = &options->rsa_authentication;
      goto parse_flag;
      
    case oRhostsRSAAuthentication:
      intptr = &options->rhosts_rsa_authentication;
      goto parse_flag;
      
    case oFallBackToRsh:
      intptr = &options->fallback_to_rsh;
      goto parse_flag;
      
    case oUseRsh:
      intptr = &options->use_rsh;
      goto parse_flag;
      
    case oIdentityFile:
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (*activep)
	{
	  if (options->num_identity_files >= SSH_MAX_IDENTITY_FILES)
	    fatal("%.200s line %d: Too many identity files specified (max %d).",
		  filename, linenum, SSH_MAX_IDENTITY_FILES);
	  options->identity_files[options->num_identity_files++] = xstrdup(cp);
	}
      break;
      
    case oUser:
      charptr = &options->user;
    parse_string:
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (*activep && *charptr == NULL)
	*charptr = xstrdup(cp);
      break;
      
    case oGlobalKnownHostsFile:
      charptr = &options->system_hostfile;
      goto parse_string;
      
    case oUserKnownHostsFile:
      charptr = &options->user_hostfile;
      goto parse_string;

    case oHostName:
      charptr = &options->hostname;
      goto parse_string;
      
    case oPort:
      intptr = &options->port;
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (cp[0] < '0' || cp[0] > '9')
	fatal("%.200s line %d: Bad number.", filename, linenum);
      value = atoi(cp);
      if (*activep && *intptr == -1)
	*intptr = value;
      break;
      
    case oCipher:
      intptr = &options->cipher;
      cp = strtok(NULL, WHITESPACE);
      value = cipher_number(cp);
      if (value == -1)
	fatal("%.200s line %d: Bad cipher.", filename, linenum);
      if (*activep && *intptr == -1)
	*intptr = value;
      break;
      
    case oRemoteForward:
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (cp[0] < '0' || cp[0] > '9')
	fatal("%.200s line %d: Badly formatted port number.", 
	      filename, linenum);
      fwd_port = atoi(cp);
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing second argument.", 
	      filename, linenum);
      if (sscanf(cp, "%255[^:]:%d", buf, &fwd_host_port) != 2)
	fatal("%.200s line %d: Badly formatted host:port.", 
	      filename, linenum);
      if (*activep)
	add_remote_forward(options, fwd_port, buf, fwd_host_port);
      break;
      
    case oLocalForward:
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (cp[0] < '0' || cp[0] > '9')
	fatal("%.200s line %d: Badly formatted port number.", 
	      filename, linenum);
      fwd_port = atoi(cp);
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing second argument.", 
	      filename, linenum);
      if (sscanf(cp, "%255[^:]:%d", buf, &fwd_host_port) != 2)
	fatal("%.200s line %d: Badly formatted host:port.", 
	      filename, linenum);
      if (*activep)
	add_local_forward(options, fwd_port, buf, fwd_host_port);
      break;
      
    case oHost:
      *activep = 0;
      while ((cp = strtok(NULL, WHITESPACE)) != NULL)
	if (match_pattern(host, cp))
	  {
	    debug("Applying options for %.100s", cp);
	    *activep = 1;
	    break;
	  }
      /* Avoid garbage check below, as strtok already returned NULL. */
      return;

    case oEscapeChar:
      intptr = &options->escape_char;
      cp = strtok(NULL, WHITESPACE);
      if (!cp)
	fatal("%.200s line %d: Missing argument.", filename, linenum);
      if (cp[0] == '^' && cp[2] == 0 && 
	  (unsigned char)cp[1] >= 64 && (unsigned char)cp[1] < 128)
	value = (unsigned char)cp[1] & 31;
      else
	if (strlen(cp) == 1)
	  value = (unsigned char)cp[0];
	else
	  if (strcmp(cp, "none") == 0)
	    value = -2;
	  else
	    {
	      fatal("%.200s line %d: Bad escape character.", 
		    filename, linenum);
	      /*NOTREACHED*/
	      value = 0; /* Avoid compiler warning. */
	    }
      if (*activep && *intptr == -1)
	*intptr = value;
      break;
      
    default:
      fatal("parse_config_file: Unimplemented opcode %d", opcode);
    }
  
  /* Check that there is no garbage at end of line. */
  if (strtok(NULL, WHITESPACE) != NULL)
    fatal("%.200s line %d: garbage at end of line.",
	  filename, linenum);
}


/* Reads the config file and modifies the options accordingly.  Options should
   already be initialized before this call.  This never returns if there
   is an error.  If the file does not exist, this returns immediately. */

void read_config_file(const char *filename, const char *host, Options *options)
{
  FILE *f;
  char line[1024];
  int active, linenum;

  /* Open the file. */
  f = fopen(filename, "r");
  if (!f)
    return;

  debug("Reading configuration data %.200s", filename);

  /* Mark that we are now processing the options.  This flag is turned on/off
     by Host specifications. */
  active = 1;
  linenum = 0;
  while (fgets(line, sizeof(line), f))
    {
      /* Update line number counter. */
      linenum++;

      process_config_line(options, host, line, filename, linenum, &active);
    }
  fclose(f);
}

/* Initializes options to special values that indicate that they have not
   yet been set.  Read_config_file will only set options with this value.
   Options are processed in the following order: command line, user config
   file, system config file.  Last, fill_default_options is called. */

void initialize_options(Options *options)
{
  memset(options, 'X', sizeof(*options));
  options->forward_agent = -1;
  options->forward_x11 = -1;
  options->rhosts_authentication = -1;
  options->rsa_authentication = -1;
  options->password_authentication = -1;
  options->rhosts_rsa_authentication = -1;
  options->fallback_to_rsh = -1;
  options->use_rsh = -1;
  options->port = -1;
  options->cipher = -1;
  options->num_identity_files = 0;
  options->hostname = NULL;
  options->user = NULL;
  options->escape_char = -1;
  options->system_hostfile = NULL;
  options->user_hostfile = NULL;
  options->num_local_forwards = 0;
  options->num_remote_forwards = 0;
}

/* Called after processing other sources of option data, this fills those
   options for which no value has been specified with their default values. */

void fill_default_options(Options *options)
{
  if (options->forward_agent == -1)
    options->forward_agent = 1;
  if (options->forward_x11 == -1)
    options->forward_x11 = 1;
  if (options->rhosts_authentication == -1)
    options->rhosts_authentication = 1;
  if (options->rsa_authentication == -1)
    options->rsa_authentication = 1;
  if (options->password_authentication == -1)
    options->password_authentication = 1;
  if (options->rhosts_rsa_authentication == -1)
    options->rhosts_rsa_authentication = 1;
  if (options->fallback_to_rsh == -1)
    options->fallback_to_rsh = 1;
  if (options->use_rsh == -1)
    options->use_rsh = 0;
  if (options->port == -1)
    options->port = 0; /* Filled in ssh_connect. */
  if (options->cipher == -1)
    options->cipher = SSH_CIPHER_NOT_SET; /* Selected in ssh_login(). */
  if (options->num_identity_files == 0)
    {
      options->identity_files[0] = 
	xmalloc(2 + strlen(SSH_CLIENT_IDENTITY) + 1);
      sprintf(options->identity_files[0], "~/%.100s", SSH_CLIENT_IDENTITY);
      options->num_identity_files = 1;
    }
  if (options->escape_char == -1)
    options->escape_char = '~';
  if (options->system_hostfile == NULL)
    options->system_hostfile = SSH_SYSTEM_HOSTFILE;
  if (options->user_hostfile == NULL)
    options->user_hostfile = SSH_USER_HOSTFILE;
  /* options->user will be set in the main program if appropriate */
  /* options->hostname will be set in the main program if appropriate */
}

