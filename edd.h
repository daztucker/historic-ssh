#define ENCRYPT 0
#define DECRYPT 1
#define QUERY 2

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#define APPEND_NEWLINE 1

#define HEADER_LENGTH 0x1000

#define EDD_VERSION "1.0"

#define VERSION_HEADER "EDD FILE V1.0\n"

/* Protocol specifies the null character as a part of the
   header string also */

#define VERSION_HEADER_LENGTH (strlen(VERSION_HEADER) + 1)
#define VERSION_NUMBER 0

#define MIN_BLOCK_SIZE 0x0010
#define MAX_BLOCK_SIZE 0xf0000

#define RANDOM_SEED_FILE "~/.ssh/random_seed"

#define DEFAULT_DIAGNOSTICS "efn"
#define DEFAULT_BLOCK_SIZE 0x1000

#define STREAM_COMMENT_MAX_LENGTH 1024
#define KEY_COMMENT_MAX_LENGTH 1024

#define PR_KEYFILE_ENV "EDD_PRIVATE"
#define PUB_KEYFILE_ENV "EDD_PUBLIC"

#define FILE_SUFFIX ".edd"

#define USAGE_REPORT \
"edd version " EDD_VERSION "\n\
Encryption: edd [options] [bits exp mod [comment]] [keyfile]\n\
Decryption: edd [options] [keyfile]\n\
Edd info:   edd -I\n\
Query:      edd [options] -q\n\
Options:\n\
            [-B] [-C comment] [-c cipher] [-d] [-D diagnostics_flags]\n\
            [-e] [-f input_file] [-F magical_input_file]\n\
            [-o output_file] [-P passphrase] [-s block_size]\n\
Diagnostics flags:\n\
            c, e, f, n, t or all. Use q for none.\n\
"
#define REPLACE_WITH_DIAGNOSE(name,flag) void name##(const char *fmt, ...) \
{ \
  va_list args; \
  va_start(args, fmt); \
  vdiagnose(flag, fmt, args, APPEND_NEWLINE); \
  va_end(args); \
}

/* Typedef of structure containing the fixed-length header parsed */
typedef struct
{
  char *version_string;
  int version, flags, cipher;
  int bits;
  MP_INT *exponent, *modulus;
  char *RSA_key_comment, *file_comment;
  MP_INT *encrypted_key;
} Header;

typedef int mode_of_operation;
typedef int bool;

extern void vdiagnose(char, const char *, va_list, int flags);
extern void diagnose(char, const char *, ...);

extern int allocate_block(int);
extern int free_block(void);
extern int read_int_block(int);
extern int write_from_block(int, int);
extern int shift_block(void);

extern char *block, *cursor;
extern int block_size, block_length;


