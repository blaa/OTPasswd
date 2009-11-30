#ifndef _PRINT_H_
#define _PRINT_H_

#include <gmp.h>

enum PRINT_LEVEL {
	PRINT_NOTICE = 1,
	PRINT_WARN = 2,
	PRINT_ERROR = 3,
	PRINT_CRITICAL = 4
};

/* Initialize logging system */
extern int print_init(int log_level, int use_stdout, int use_syslog, const char *log_file);

/* Clean up after logging */
extern void print_fini();

/* Log some data */
extern int print(int level, const char *fmt, ...);

/* Log data and preceed it with perror message */
extern int print_perror(int level, const char *fmt, ...);

/* Return number in base which doesn't need to be freed */
extern const char *print_mpz(const mpz_t number, int base);
#endif
