/* maximum file descriptors = 1024 */

struct Min_Auth_Fd {
  int fd;
  char shell[32];
};

static struct Min_Auth_Fd mafd[] = {
  { 4, "sh" },
  { 4, "jsh" },
  { 4, "ksh" },
  { 20, "tcsh" },
  { 4, "bash" },
  { 64, "zsh" },
  { 0, "" },
};

#define MAFD_MAX (sizeof (mafd) / sizeof (mafd[0]) - 1)
