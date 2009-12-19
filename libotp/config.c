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
#include <string.h>

/* getpwnam */
#include <sys/types.h>
#include <pwd.h>

#include "print.h"
#include "config.h"

/* Set all fields to default values */
static void _config_defaults(options *opt)
{
	const options o = {
		/* Field description near options struct declaration */
		.db = CONFIG_DB_GLOBAL,
		.global_db_path = "/etc/otshadow",
		.user_db_path = ".otpasswd",

		.enforce = 0,
		.secure = 1,
		.logging = 1,
		.silent = 0,
		.retry = 0,
		.show = 1,
		.oob = 0,
		.oob_path = "",

		.allow_key_generation = 1,
		.allow_skipping = 1,
		.allow_passcode_print = 1,
		.allow_key_print = 1,
		
		.def_passcode_length = 4,
		.min_passcode_length = 2,
		.max_passcode_length = 16,
		.def_alphabet_length = 64,
		.min_alphabet_length = 64,
		.max_alphabet_length = 88,
		.allow_salt = 1,
	};
	*opt = o;
}

/* Parse config file and set fields in struct 
 * config_path might be NULL to read default config.
 */
static int _config_parse(options *opt, const char *config_path)
{
	int retval = 1;
	int line_count = 0;
	FILE *f;

	char line_buf[CONFIG_MAX_LINE_LEN];
	
	if (config_path) {
		f = fopen(config_path, "r");
	} else {
		f = fopen(CONFIG_PATH, "r");
	}

	if (!f) {
		print_perror(PRINT_ERROR, "Unable to open config file!\n");
		return 1;
	}

	do {
		int line_length;

		/* Read line */
		if (fgets(line_buf, sizeof(line_buf), f) == NULL)
			break;

		/* Check line too long condition */
		line_length = strlen(line_buf);
		if (line_length == sizeof(line_buf) - 1 && 
		    line_buf[line_length-1] != '\n') {
			print(PRINT_ERROR, "Line in config file to long.\n");
			goto error;
		}

		/* Remove trailing \n */
		line_length--;
		line_buf[line_length] = '\0';
		
		line_count++;

		/* Omit comments */
		if (line_buf[0] == '#')
			continue;

		/* Omit all-whitespace */
		char *ptr = line_buf;
		for (; *ptr == ' ' || *ptr == '\t'; ptr++);

		if (*ptr == '\0') {
			/* We got to the end of line - it's all whitespace.
			 * Omit it */
			continue;
		}

		/* Find = */
		char *equality = strchr(line_buf, '=');

		if (!equality) {
			print(PRINT_ERROR, "Syntax error on line %d in config file.", 
			      line_count);
			goto error;
		}
		
		/* After those two lines equality points to the start
		 * of argument, and buf_line to the name of variable
		 * we are setting (nul-terminated)
		 */
		*equality = '\0';
		equality++;

		/* Try to parse argument as int */
		int arg;
		int arg_state = sscanf(equality, "%d", &arg);

		/* Helper macro to ensure all parameters
		 * have correct values */
#define REQUIRE_ARG(from, to)					\
	do {							\
		if (arg_state != 1) {				\
			print(PRINT_ERROR,			\
			      "Unable to parse int argument"	\
			      " in config at line %d\n",	\
			      line_count);			\
			goto error;				\
		}						\
		if (arg < (from) || arg > (to)) {		\
			print(PRINT_ERROR,			\
			      "Number argument (%d) out of"	\
			      " range (%d;%d) in config "	\
			      "at line %d.\n",			\
			      arg, from, to, line_count);	\
			goto error;				\
		}						\
	} while (0)

		/* Check equality */
#define _EQ(A, B) (strcasecmp((A), (B)) == 0)

		/* Check length, copy and secure with \0 */
#define _COPY(to, from)						\
	do {							\
		if (strlen(from) > sizeof(to)-1) {		\
			print(PRINT_ERROR,			\
			      "Value too long at line %d "	\
			      "of config file.\n", line_count);	\
			goto error;				\
		}						\
		strncpy(to, from, sizeof(to)-1);		\
	} while (0) 

		/* Parsing general configuration */
		if (_EQ(line_buf, "db")) {
			if (_EQ(equality, "global")) 
				opt->db = CONFIG_DB_GLOBAL;
			else if (_EQ(equality, "user")) 
				opt->db = CONFIG_DB_USER;
			else if (_EQ(equality, "mysql")) 
				opt->db = CONFIG_DB_MYSQL;
			else if (_EQ(equality, "ldap")) 
				opt->db = CONFIG_DB_LDAP;
			else {
				print(PRINT_ERROR,
				      "Illegal db parameter at line"
				      " %d in config file\n", line_count);
				goto error;
			}

		} else if (_EQ(line_buf, "global_db")) {
			_COPY(opt->global_db_path, equality);
		} else if (_EQ(line_buf, "user_db")) {
			_COPY(opt->user_db_path, equality);

		/* Ignore for now */
		} else if (_EQ(line_buf, "sql_host")) {
			_COPY(opt->sql_host, equality);
		} else if (_EQ(line_buf, "sql_database")) {
			_COPY(opt->sql_database, equality);
		} else if (_EQ(line_buf, "sql_user")) {
			_COPY(opt->sql_user, equality);
		} else if (_EQ(line_buf, "sql_pass")) {
			_COPY(opt->sql_pass, equality);

		/* Parsing PAM configuration */
		} else if (_EQ(line_buf, "show")) {
			REQUIRE_ARG(1,3);
			opt->show = arg;
		} else if (_EQ(line_buf, "enforce")) {
			REQUIRE_ARG(0, 1);
			opt->enforce = arg;
		} else if (_EQ(line_buf, "retry")) {
			REQUIRE_ARG(0, 3);
			opt->retry = arg;
		} else if (_EQ(line_buf, "retries")) {
			REQUIRE_ARG(2, 5);
			opt->retry = arg;
		} else if (_EQ(line_buf, "logging")) {
			REQUIRE_ARG(0, 2);
			opt->logging = arg;
		} else if (_EQ(line_buf, "silent")) {
			REQUIRE_ARG(0, 1);
			opt->silent = arg;
		} else if (_EQ(line_buf, "oob")) {
			REQUIRE_ARG(0, 2);
			opt->oob = arg;
		} else if (_EQ(line_buf, "oob_user")) {
			struct passwd *pwd;
			pwd = getpwnam(equality);
			if (pwd == NULL) {
				print(PRINT_ERROR,
				      "Illegal user specified in config "
				      "at line %d.\n", line_count);
				goto error;
			}
			opt->uid = pwd->pw_uid;
			opt->gid = pwd->pw_gid;
		} else if (_EQ(line_buf, "oob_path")) {
			_COPY(opt->oob_path, equality);

		/* Parsing POLICY configuration */
		} else if (_EQ(line_buf, "allow_skipping")) {
			REQUIRE_ARG(0, 1);
			opt->allow_skipping = arg;
		} else if (_EQ(line_buf, "allow_passcode_print")) {
			REQUIRE_ARG(0, 1);
			opt->allow_passcode_print = arg;
		} else if (_EQ(line_buf, "allow_key_print")) {
			REQUIRE_ARG(0, 1);
			opt->allow_key_print = arg;
		} else if (_EQ(line_buf, "allow_key_generation")) {
			REQUIRE_ARG(0, 1);
			opt->allow_key_generation = arg;
		} else if (_EQ(line_buf, "allow_salt")) {
			REQUIRE_ARG(0, 2);
			opt->allow_salt = arg;

		} else if (_EQ(line_buf, "def_passcode_length")) {
			REQUIRE_ARG(2, 16);
			opt->def_passcode_length = arg;
		} else if (_EQ(line_buf, "min_passcode_length")) {
			REQUIRE_ARG(2, 16);
			opt->min_passcode_length = arg;

		} else if (_EQ(line_buf, "max_passcode_length")) {
			REQUIRE_ARG(2, 16);
			opt->max_passcode_length = arg;

		} else if (_EQ(line_buf, "def_alphabet_length")) {
			REQUIRE_ARG(64, 88);
			opt->def_alphabet_length = arg;
		} else if (_EQ(line_buf, "min_alphabet_length")) {
			REQUIRE_ARG(64, 88);
			opt->min_alphabet_length = arg;
		} else if (_EQ(line_buf, "max_alphabet_length")) {
			REQUIRE_ARG(64, 88);
			opt->max_alphabet_length = arg;
		} else {
			/* Error */
			print(PRINT_ERROR, "Unrecognized variable '%s' on line %d in config file\n",
			      line_buf, line_count);
			goto error;
		}

	} while (!feof(f));

	/* All ok */
	retval = 0;
error:
	fclose(f);
	return retval;
}

static int _config_init(options *opt, const char *config_path)
{
	int retval;
	_config_defaults(opt);
	retval = _config_parse(opt, config_path);

	if (retval != 0) {
		_config_defaults(opt);
	}

	return retval;
}

options *config_get(void)
{
	/* Here is stored our global structure */
	static options opt;
	static options *opt_init = NULL;

	int retval;

	if (opt_init)
		return opt_init;

	retval = _config_init(&opt, CONFIG_PATH);
	if (retval != 0)
		return NULL;
	
	opt_init = &opt;

	return opt_init;
}

