/* maximum file descriptors = 3240 */

struct Min_Auth_Fd {
  int fd;
  char shell[32];
};

static struct Min_Auth_Fd mafd[] = {
  { 4, "sh" },
  { 64, "csh" },
  { 64, "zsh" },
  { 0, "" },
};

#define MAFD_MAX (sizeof (mafd) / sizeof (mafd[0]) - 1)
