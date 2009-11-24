#ifndef _PRINT_H_
#define _PRINT_H_

enum PRINT_LEVEL {
	PRINT_NOTICE = 1,
	PRINT_WARN = 2,
	PRINT_ERROR = 3,
	PRINT_CRITICAL = 4
};

extern int print_init(int log_level, int use_stdout, int use_syslog, const char *log_file);

extern int print(int level, const char *fmt, ...);
extern int print_perror(int level, const char *intro);
#endif
