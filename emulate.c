#include "includes.h"
#include "ssh.h"
#include "emulate.h"

unsigned long emulation_information = 0;

/* check_emulation: take the remote party's version number as
   arguments and return our possibly modified version number back
   (relevant only for clients).

   Return value will be 0 if we can work together,

   EMULATE_VERSION_TOO_OLD if the other party has too old version
   which we cannot emulate,

   EMULATE_VERSION_REALLY_TOO_OLD if the other party has so old
   version that we don't want to do anything with it (probably
   the other party does not understand anything about different
   versions...),

   EMULATE_MAJOR_VERSION_MISMATCH if the other party has different
   major version and thus will probably not understand anything we
   say, and

   EMULATE_VERSION_TOO_NEW if the other party has never code than we
   have.

   */

int check_emulation(int her_major_version, int her_minor_version,
		    int *return_major, int *return_minor)
{
  int new_major = PROTOCOL_MAJOR;
  int new_minor = PROTOCOL_MINOR;
  int my_error = 0;
  
  int major_diff = ((her_major_version > PROTOCOL_MAJOR) ?
		    1 : ((her_major_version < PROTOCOL_MAJOR) ?
			 -1 : 0));
  int minor_diff = ((her_minor_version > PROTOCOL_MINOR) ?
		    1 : ((her_minor_version < PROTOCOL_MINOR) ?
			 -1 : 0));
  int total_diff = (major_diff ? major_diff
		    : minor_diff);

  if (her_major_version <= 1 && her_minor_version <= 4)
    {
      emulation_information |= EMULATE_OLD_AGENT_BUG;
      debug("Agent forwarding will be disabled because of protocol version mismatch");
    }
  switch (total_diff)
    {
    case -1:
      /* The remote software is older than we are.
	 Check if we could emulate it. */
      if (!major_diff)
	{
	  /* She has same major number as we, but is otherways older. */
	  if (her_minor_version == 0)
	    my_error = EMULATE_VERSION_REALLY_TOO_OLD;
	  else
	    {
	      debug("Old channel code will be emulated.");
	      emulation_information |= EMULATE_OLD_CHANNEL_CODE;
	      new_minor = her_minor_version;
	    }
	  /* return EMULATE_VERSION_TOO_OLD if the other party has old
	     code which we cannot emulate but is not too old not to
	     shake hands with. */
	}
      else
	my_error = EMULATE_MAJOR_VERSION_MISMATCH;
      break;
    case 0:
      /* The remote software is same version as we are -
	 excellent! */
      break;
    case 1:
      /* The remote software is newer than we. If we are the client,
	 no matter - the server will decide. If we are the server, we
	 cannot emulate a newer client and decide to stop. */
      my_error = EMULATE_VERSION_TOO_NEW;
      if (major_diff)
	my_error = EMULATE_MAJOR_VERSION_MISMATCH;
      break;      
    }
  if (return_major)
    *return_major = new_major;
  if (return_minor)
    *return_minor = new_minor;
  return my_error;
}
