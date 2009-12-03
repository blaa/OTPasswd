/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with otpasswd. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/

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
