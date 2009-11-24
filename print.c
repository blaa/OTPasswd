#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "print.h"

/* Currently used print_level */
struct log_state {
	/* Log messages of level equal or greater to print_level */
	int print_level;
	int use_stdout; /* Log to stdout if 1, stderr if 2 */
	int use_syslog; /* Log to syslog if 1 */
	FILE *log_file;	/* Log to file if not null */
} log_state;

struct log_state log_state;

int print_init(int print_level, int use_stdout, int use_syslog, const char *log_file)
{
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

	return 0;
}


int print(int level, const char *fmt, ...)
{
	int ret;
	char buff[512]; 
	char *intro;

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
		break;
	case PRINT_WARN:
		intro = "WARNING: ";
		break;
	case PRINT_ERROR:
		intro = "ERROR:   ";
		break;
	case PRINT_CRITICAL:
		intro = "CRITICAL: ";
		break;
	default:
		intro = "Unknown: ";
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
		printf("Unimplemented!\n");
		assert(0);
	}

	/* log file */
	if (log_state.log_file) {
		fputs(intro, log_state.log_file);
		fputs(buff, log_state.log_file);
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

	if (ret > 0 || ret < sizeof(buff)) {
		return 2;
	}


	return print(level, "%s: %s\n", buff, error);
}

