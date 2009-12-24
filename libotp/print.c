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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <gmp.h>

#include "print.h"


/* Currently used print_level */
struct log_state {
	/* Log messages of level equal or greater to print_level */
	int initialized;
	int print_level;
	int use_stdout; /* Log to stdout if 1, stderr if 2 */
	int use_syslog; /* Log to syslog if 1 */
	FILE *log_file;	/* Log to file if not null */

	/* Last number converted */
	char *number;
} log_state = {0};

struct log_state log_state;

int print_init(int print_level, int use_stdout, int use_syslog, const char *log_file)
{
	if (log_state.initialized)
		print_fini();

	log_state.print_level = print_level;
	log_state.use_stdout = use_stdout;
	log_state.use_syslog = use_syslog;

	if (log_file) {
		log_state.log_file = fopen(log_file, "a");
	
		if (!log_state.log_file) {
			printf("Unable to open log file\n");
			perror("fopen");
			return 1;
		}
	} else 
		log_state.log_file = NULL;

	log_state.initialized = 1;
	return 0;
}


int print(int level, const char *fmt, ...)
{
	int ret;
	char buff[512]; 
	char *intro;
	int syslog_level = LOG_INFO;

	assert(log_state.initialized == 1);

	if (log_state.print_level == 0) {
		printf("Attempted to use print subsystem without initialization\n");
		assert(0);
		return 1;
	}

	if (level < log_state.print_level)
		return 1;

	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(buff, sizeof(buff), fmt, ap);
	va_end(ap);

	/* Ensure we log everything or fail at all */
	assert(ret > 0);
	assert(ret < sizeof(buff));

	if (ret <= 0 || ret >= sizeof(buff)) {
		return 2;
	}

	/* Generate intro */
	switch (level) {
	case PRINT_NOTICE:
		intro = "NOTICE:  ";
		syslog_level = LOG_NOTICE;
		break;
	case PRINT_WARN:
		intro = "WARNING: ";
		syslog_level = LOG_WARNING;
		break;
	case PRINT_ERROR:
		intro = "ERROR:   ";
		syslog_level = LOG_ERR;
		break;
	case PRINT_CRITICAL:
		intro = "CRITICAL: ";
		syslog_level = LOG_CRIT;
		break;
	default:
		intro = "Unknown: ";
		syslog_level = LOG_INFO;
		break;

	}


	/* stdout */
	switch (log_state.use_stdout) {
	case 1:
		fputs(intro, stdout);
		fputs(buff, stdout);
		break;
	case 2:
		fputs(intro, stderr);
		fputs(buff, stderr);
		break;
	default:
		break;
	}

	/* syslog */
	if (log_state.use_syslog) {
		openlog("otpasswd", LOG_CONS | LOG_PID, LOG_AUTHPRIV);
		syslog(syslog_level, "%s%s", intro, buff); /* FIXME; is intro needed? */
		closelog();
	}

	/* log file */
	if (log_state.log_file) {
		fputs(intro, log_state.log_file);
		fputs(buff, log_state.log_file);
		fflush(log_state.log_file);
	}
	return 0;
}


int print_perror(int level, const char *fmt, ...)
{
	char buff[512]; 

	const char *error = strerror(errno);
	int ret;

	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(buff, sizeof(buff), fmt, ap);
	va_end(ap);

	/* Ensure we log everything or fail at all */
	assert(ret > 0);
	assert(ret < sizeof(buff));

	if (!(ret > 0 && ret < sizeof(buff))) {
		return 2;
	}
	
	return print(level, "%s (%s)\n", buff, error);
}

void print_fini()
{
	if (log_state.log_file)
		fclose(log_state.log_file);

	free(log_state.number);

	log_state.initialized = 0;
}

const char *print_mpz(const mpz_t number, int base)
{
	free(log_state.number);
	log_state.number = mpz_get_str(NULL, base, number);
	return log_state.number;
}
