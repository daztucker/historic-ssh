/*

canohost.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul  2 17:52:22 1995 ylo
Last modified: Wed Jul  5 23:54:42 1995 ylo

*/

#include "includes.h"
#include "packet.h"
#include "xmalloc.h"
#include "ssh.h"

static struct sockaddr_in canonical_host_addr;
static char *canonical_host_name = NULL;

/* Return the canonical name of the host in the other side of the current
   connection (as returned by packet_get_connection).  The host name is
   cached, so it is efficient to call this several times. */

const char *get_canonical_hostname()
{
  struct sockaddr_in from;
  int fromlen, i, socket;
  struct hostent *hp;
  char name[512];

  /* Get client socket. */
  socket = packet_get_connection();

  /* Get IP address of client. */
  fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));
  if (getpeername(socket, (struct sockaddr *)&from, &fromlen) < 0)
    {
      error("getpeername failed");
      return NULL;
    }

  /* Check if we have previously retrieved this same name. */
  if (canonical_host_name != NULL)
    {
      /* Return the cached name if they match. */
      if (memcmp(&canonical_host_addr, &from, sizeof(from)) == 0)
	return canonical_host_name;

      /* Otherwise free the cached value. */
      xfree(canonical_host_name);
      canonical_host_name = NULL;
    }
  
  /* Map the IP address to a host name. */
  hp = gethostbyaddr((char *)&from.sin_addr, sizeof(struct in_addr),
		     from.sin_family);
  if (hp)
    {
      /* Got host name. */
      strncpy(name, hp->h_name, sizeof(name));
      name[sizeof(name) - 1] = '\0';
      
      /* Convert it to all lowercase (which is expected by the rest of this
	 software). */
      for (i = 0; name[i]; i++)
	if (isupper(name[i]))
	  name[i] = tolower(name[i]);

      /* Map it back to an IP address and check that the given address actually
	 is an address of this host.  This is necessary because anyone with
	 access to a name server can define arbitrary names for an IP address.
	 Mapping from name to IP address can be trusted better (but can still
	 be fooled if the intruder has access to the name server of the
	 domain). */
      hp = gethostbyname(name);
      if (!hp)
	{
	  log("reverse mapping checking gethostbyname for %.700s failed - POSSIBLE BREAKIN ATTEMPT!", name);
	  return NULL;
	}
      /* Look for the address from the list of addresses. */
      for (i = 0; hp->h_addr_list[i]; i++)
	if (memcmp(hp->h_addr_list[i], &from.sin_addr, sizeof(from.sin_addr))
	    == 0)
	  break;
      /* If we reached the end of the list, the address was not there. */
      if (!hp->h_addr_list[i])
	{
	  /* Address not found for the host name. */
	  log("Address %.100s maps to %.600s, but this does not map back to the address - POSSIBLE BREAKIN ATTEMPT!",
	      inet_ntoa(from.sin_addr), name);
	  return 0;
	}
      /* Address was found for the host name.  We accept the host name. */
    }
  else
    {
      /* Host name not found.  Use ascii representation of the address. */
      strcpy(name, inet_ntoa(from.sin_addr));
      log("Could not reverse map address %.100s.", name);
    }
  
#ifdef IP_OPTIONS
  /* If IP options are supported, make sure there are none (log and clear
     them if any are found).  Basically we are worried about source routing;
     it can be used to pretend you are somebody (ip-address) you are not.
     That itself may be "almost acceptable" under certain circumstances,
     but rhosts autentication is useless if source routing is accepted.
     Notice also that if we just dropped source routing here, the other
     side could use IP spoofing to do rest of the interaction and could still
     bypass security.  So we exit here if we detect any IP options. */
  {
    unsigned char options[200], *ucp;
    char text[1024], *cp;
    int option_size, ipproto;
    struct protoent *ip;
    
    if ((ip = getprotobyname("ip")) != NULL)
      ipproto = ip->p_proto;
    else
      ipproto = IPPROTO_IP;
    option_size = sizeof(options);
    if (getsockopt(0, ipproto, IP_OPTIONS, (char *)options,
		   &option_size) >= 0 && option_size != 0)
      {
	cp = text;
	/* Note: "text" buffer must be at least 3x as big as options. */
	for (ucp = options; option_size > 0; ucp++, option_size--, cp += 3)
	  sprintf(cp, " %2.2x", *ucp);
	log("Connection from %.100s with IP options:%.800s",
	    inet_ntoa(from.sin_addr), text);
	packet_disconnect("Connection from %.100s with IP options:%.800s", 
			  inet_ntoa(from.sin_addr), text);
      }
  }
#endif

  canonical_host_name = xstrdup(name);
  memcpy(&canonical_host_addr, &from, sizeof(from));
  return canonical_host_name;
}
