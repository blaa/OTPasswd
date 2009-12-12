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

#include "print.h"
#include "config.h"

int config_parse(options *opt, const char *config_path)
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
		char *last_char = line_buf + sizeof(line_buf) - 2;
		/* Mark the end of line */
		*last_char = '\0';

		/* Read line */
		if (fgets(line_buf, sizeof(line_buf), f) == NULL)
			break;

		/* Check line too long condition */
		if (*last_char != '\n' || *last_char != '\0') {
			print(PRINT_ERROR, "Line in config file to long");
			goto error;
		}

		line_count++;

		/* Omit comments */
		if (line_buf[0] == '#')
			continue;

		/* Omit all-whitespace */
		char *ptr = line_buf;
		for (; *ptr != '\0' && *ptr == '\n' && *ptr != ' ' &&
			*ptr != '\t'; ptr++);

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


		if (strcasecmp(line_buf, "show") == 0) {
			REQUIRE_ARG(1,3);
			opt->show = arg;
		} else if (strcasecmp(line_buf, "enforce") == 0) {
			REQUIRE_ARG(0, 1);
			opt->enforce = arg;
		} else if (strcasecmp(line_buf, "retry") == 0) {
			REQUIRE_ARG(0, 3);
			opt->retry = arg;
		} else if (strcasecmp(line_buf, "debug") == 0) {
			REQUIRE_ARG(0, 1);
			opt->debug = arg;
		} else if (strcasecmp(line_buf, "oob") == 0) {
			REQUIRE_ARG(0, 2);
			opt->oob = arg;
		} else if (strcasecmp(line_buf, "oob_path") == 0) {
		} else if (strcasecmp(line_buf, "uid") == 0) {
			REQUIRE_ARG(0, 9999999);
			opt->uid = arg;
		} else if (strcasecmp(line_buf, "gid") == 0) {
			REQUIRE_ARG(0, 9999999);
			opt->gid = arg;
		} else if (strcasecmp(line_buf, "use_global_db") == 0) {
			REQUIRE_ARG(0, 1);
			opt->use_global_db = arg;
		} else if (strcasecmp(line_buf, "global_db") == 0) {
		} else if (strcasecmp(line_buf, "user_db") == 0) {
		} else if (strcasecmp(line_buf, "allow_skipping") == 0) {
			REQUIRE_ARG(0, 1);
			opt->allow_skipping = arg;
		} else if (strcasecmp(line_buf, "allow_passode_print") == 0) {
			REQUIRE_ARG(0, 1);
			opt->allow_passcode_print = arg;
		} else if (strcasecmp(line_buf, "allow_key_print") == 0) {
			REQUIRE_ARG(0, 1);
			opt->allow_key_print = arg;
		} else if (strcasecmp(line_buf, "allow_key_generation") == 0) {
			REQUIRE_ARG(0, 1);
			opt->allow_key_generation = arg;
		} else if (strcasecmp(line_buf, "min_passcode_length") == 0) {
			REQUIRE_ARG(2, 16);
			opt->min_passcode_length = arg;
		} else if (strcasecmp(line_buf, "max_passcode_length") == 0) {
			REQUIRE_ARG(2, 16);
			opt->max_passcode_length = arg;
		} else if (strcasecmp(line_buf, "min_alphabet_length") == 0) {
			REQUIRE_ARG(64, 88);
			opt->min_alphabet_length = arg;
		} else if (strcasecmp(line_buf, "max_alphabet_length") == 0) {
			REQUIRE_ARG(64, 88);
			opt->max_alphabet_length = arg;
		} else if (strcasecmp(line_buf, "salt") == 0) {
			REQUIRE_ARG(0, 2);
			opt->salt = arg;
		} else {
			/* Error */
			print(PRINT_ERROR, "Unrecognized variable on line %d in config file\n",
			      line_count);
		}

	} while (!feof(f));

	/* All ok */
	retval = 0;
error:
	fclose(f);
	return retval;
}


