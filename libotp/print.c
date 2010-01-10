/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009, 2010 by Tomasz bla Fortuna <bla@thera.be>
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

const int PRINT_LEVEL_MASK = 0x3F;

/* Currently used print_level */
struct log_state {
	/* Log messages of level equal or greater to print_level */
	int initialized;
	int flags;
	FILE *log_file;	/* Log to file if not null */
} log_state = {0};

struct log_state log_state;

int print_init(int flags, const char *log_file)
{
	if (log_state.initialized)
		print_fini();

	log_state.flags = flags;

	if (log_file) {
		log_state.log_file = fopen(log_file, "a");
	
		if (!log_state.log_file) {
			log_state.flags = 0;
			return 1;
		}
	} else {
		log_state.log_file = NULL;
	}

	log_state.initialized = 1;
	return 0;
}

void print_config(int flags)
{
	assert(log_state.initialized == 1);
	log_state.flags = flags;
}

int _print(const char *file, const int line, int level, const char *fmt, ...)
{
	int ret;
	char buff[512]; 
	char *intro;
	int syslog_level = LOG_INFO;

	assert(log_state.initialized == 1);

	const int print_level = log_state.flags & PRINT_LEVEL_MASK;
	const int use_stdout = log_state.flags & PRINT_STDOUT;
	const int use_syslog = log_state.flags & PRINT_SYSLOG;

	if (level < print_level)
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
	switch (use_stdout) {
	case 1:
		if (file) {
			char *base = strrchr(file, '/') + 1;
			if (!base) file = base;
			fprintf(stdout, "%s:%d ", base, line);
		}
		fputs(intro, stdout);
		fputs(buff, stdout);
		break;
	case 2:
		if (file) {
			char *base = strrchr(file, '/') + 1;
			if (!base) file = base;
			fprintf(stderr, "%s:%d ", base, line);
		}
		fputs(intro, stderr);
		fputs(buff, stderr);
		break;
	default:
		break;
	}

	/* syslog */
	if (use_syslog) {
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


int _print_perror(const char *file, int line, int level, const char *fmt, ...)
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
	
	return _print(file, line, level, "%s (%s)\n", buff, error);
}

void print_fini()
{
	if (log_state.log_file)
		fclose(log_state.log_file);

	log_state.initialized = 0;
}
