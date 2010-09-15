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
#include <string.h>
#include <assert.h>

/* For alphabet tests */
#include <ctype.h>

/* getpwnam */
#include <sys/types.h>
#include <pwd.h>

/* stat */
#include <sys/stat.h>
#include <unistd.h>

#include "ppp.h"

static int _alphabet_check(const char *alphabet) {
	/* Check duplicates and character range. */
	char count[128] = {0};
	const char *ptr;

	for (ptr = alphabet; *ptr; ptr++) {
		const unsigned int tmp = *ptr;

		if (!isascii(tmp)) {
			print(PRINT_ERROR,
			      "Config error: Custom alphabet contains "
			      "non-ascii character.\n");
			return 1;
		}

		if (!isgraph(tmp)) {
			if (isspace(tmp))
				print(PRINT_ERROR,
				      "Config error: Custom alphabet contains "
				      "whitespace character.\n");
			else
				print(PRINT_ERROR,
				      "Config error: Custom alphabet contains "
				      "non-printable, non-whitespace character.\n");
			return 1;
		}

		if (count[tmp]) {
			print(PRINT_ERROR,
			      "Config error: Custom alphabet contains "
			      "duplicate character: %c.\n", tmp);
			return 1;
		}
		count[tmp]++;
	}
	return 0;
}

static void _right_trim(char *arg)
{
	char *ptr;

	/* Nothing to do, empty string? */
	if (!arg)
		return;

	if (*arg == '\0')
		return;

	/* Find end */
	for (ptr = arg; *ptr; ptr++);

	/* Point it at last character */
	ptr--;

	/* Go to the beginning until non-whitespace
	 * is found or first character */
	for (; ptr > arg && isspace(*ptr); ptr--);

	/* Cut string here */
	ptr++;
	*ptr = '\0';
}

/* Set all fields to default values */
static void _config_defaults(cfg_t *cfg)
{
	const cfg_t o = {
		/* Field description near cfg struct declaration */
		.user_uid = -1,
		.user_gid = -1,

		.db = CONFIG_DB_UNCONFIGURED,
		.global_db_path = "/etc/otpasswd/otshadow",
		.user_db_path = ".otpasswd",

		.sql_host = "localhost",
		.sql_database = "otpasswd",
		.sql_user = "",
		.sql_pass = "",

		.ldap_host = "localhost",
		.ldap_dn = "",
		.ldap_user = "",
		.ldap_pass = "",

		.pam_logging = 2,
		.pam_silent = CONFIG_DISABLED,
		.pam_enforce = CONFIG_DISABLED,
		.pam_enforce_policy = CONFIG_ENABLED,
		.pam_retry = 0,
		.pam_retries = 3,

		.pam_key_regeneration_prompt = 0,
		.pam_failure_warning = 1,
		.pam_failure_boundary = 3,
		.pam_failure_delay = 5,
		.pam_spass_require = 0,

		.pam_oob = 0,
		.pam_oob_path = "/etc/otpasswd/otpasswd_oob.sh",
		.pam_oob_uid = -1,
		.pam_oob_gid = -1,
		.pam_oob_delay = 10,

		.key_generation = CONFIG_ALLOW,
		.key_regeneration = CONFIG_ALLOW,
		.disabling = CONFIG_DISALLOW,
		.sourced_key_generation = CONFIG_DISALLOW,
		.key_removal = CONFIG_ALLOW,
		.passcode_print = CONFIG_ALLOW,
		.key_print = CONFIG_ALLOW,
		.skipping = CONFIG_ALLOW,

		.shell_auth = CONFIG_ALLOW,
		.state_import = CONFIG_DISALLOW,
		.state_export = CONFIG_ALLOW,
		.contact_change = CONFIG_ALLOW,
		.label_change = CONFIG_ALLOW,

		.spass_change = CONFIG_ALLOW,
		.spass_min_length = 7,
		.spass_require_digit  = 1,
		.spass_require_special = 1,
		.spass_require_uppercase = 1,

		.passcode_def_length = 4,
		.passcode_min_length = 2,
		.passcode_max_length = 16,

		.alphabet_change = CONFIG_ALLOW,
		.alphabet_def = 1,
		.alphabet_min_length = 32,
		.alphabet_max_length = 88,

		.alphabet_custom = "0123456789",

		.salt = CONFIG_ALLOW,
		.salt_def = CONFIG_ENABLED,

		.show_def = CONFIG_ALLOW,
		.show = CONFIG_ENABLED,
	};
	*cfg = o;
}


/*** Helper macros ***/
/* Check equality */
#define _EQ(A, B) (strcasecmp((A), (B)) == 0)

/* Parse config file and set fields in struct
 * config_path might be NULL to read default config.
 */
static int _config_parse(cfg_t *cfg, const char *config_path)
{
	int fail = 0;
	int retval = 1;
	int line_count = 0;
	FILE *f;

	char line_buf[CONFIG_MAX_LINE_LEN];

	/* TODO/FIXME: Check if config is owned by root */

	if (config_path) {
		f = fopen(config_path, "r");
	} else {
		f = fopen(CONFIG_PATH, "r");
	}

	if (!f) {
		return 1;
	}

	do {
		int line_length;

		/* Read line */
		if (fgets(line_buf, sizeof(line_buf), f) == NULL)
			break;

		/* Check line-too-long condition */
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

		/* Parse standard argument values */
		int arg;
		/* 1 - int, 2 - (DIS)ALLOW/ENFORCE, 3 - ENABLED/DISABLED */
		int arg_state; 

		/* Try to parse argument as int */
		arg_state = sscanf(equality, "%d", &arg);

		/* Try to parse argument as string-value */
		if (arg_state == 0) {
			if (_EQ(equality, "enabled")) {
				arg_state = 3;
				arg = CONFIG_ENABLED;
			} else if (_EQ(equality, "disabled")) {
				arg_state = 3;
				arg = CONFIG_DISABLED;
			} else if (_EQ(equality, "disallow")) {
				arg_state = 2;
				arg = CONFIG_DISALLOW;
			} else if (_EQ(equality, "allow")) {
				arg_state = 2;
				arg = CONFIG_ALLOW;
			} else if (_EQ(equality, "enforce")) {
				arg_state = 2;
				arg = CONFIG_ENFORCE;
			}
		}

		/* Helper macros to ensure all parameters
		 * have correct values */
#define REQUIRE_INT_ARG(from, to)				\
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
			      "Argument (%d) of \"%s\" out of"	\
			      " range (%d;%d) in config "	\
			      "at line %d.\n",			\
			      arg, line_buf, from, to,		\
			      line_count);			\
			goto error;				\
		}						\
	} while (0)

#define REQUIRE_ED_ARG()					\
	do {							\
		if (arg_state != 3) {				\
			print(PRINT_ERROR,			\
			      "Argument neither 'enabled' nor "	\
			      "'disabled' at line %d.\n",	\
			      line_count);			\
			goto error;				\
		}						\
	} while (0)

		/* x - turns on acceptance of ENFORCE parameter */
#define REQUIRE_DAE_ARG(x)					\
	do {							\
		if (arg_state != 2) {				\
			print(PRINT_ERROR,			\
			      "Argument is neither 'disallow', "	\
			      "'allow' nor 'enforce' at line %d.\n",	\
			      line_count);			\
			goto error;				\
		}						\
		if (x == 0 && arg == CONFIG_ENFORCE) {		\
			print(PRINT_ERROR,			\
			      "Only 'allow' or 'disallow' "	\
			      "parameter accepted at line %d.\n",	\
			      line_count);			\
			goto error;				\
		}						\
	} while (0)



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
		_right_trim(to);				\
	} while (0)

		/* Parsing general configuration */
		if (_EQ(line_buf, "user")) {
			struct passwd *pwd;
			/* Ignore if DB=user */
			if (cfg->db != CONFIG_DB_USER) {
				pwd = getpwnam(equality);
				if (pwd == NULL) {
					print(PRINT_ERROR,
					      "Config Error: Illegal user specified in config "
					      "at line %d.\n", line_count);
					goto error;
				}
				cfg->user_uid = pwd->pw_uid;
				cfg->user_gid = pwd->pw_gid;
				endpwent();

				if (cfg->user_uid == 0) {
					print(PRINT_ERROR,
					      "Config Error: USER variable is set to root.");
					goto error;
				}
			}
		} else if (_EQ(line_buf, "db")) {
			_right_trim(equality);
			if (_EQ(equality, "global"))
				cfg->db = CONFIG_DB_GLOBAL;
			else if (_EQ(equality, "user"))
				cfg->db = CONFIG_DB_USER;
			else if (_EQ(equality, "mysql"))
				cfg->db = CONFIG_DB_MYSQL;
			else if (_EQ(equality, "ldap"))
				cfg->db = CONFIG_DB_LDAP;
			else {
				print(PRINT_ERROR,
				      "Illegal db parameter at line"
				      " %d in config file\n", line_count);
				goto error;
			}
		} else if (_EQ(line_buf, "db_user")) {
			if (strchr(equality, '/') != NULL) {
				print(PRINT_ERROR,
				      "Config Error at %d: DB_USER config option musn't contain slashes.\n", line_count);
				goto error;
			}
			_COPY(cfg->user_db_path, equality);

		/* SQL Configuration */
		} else if (_EQ(line_buf, "sql_host")) {
			_COPY(cfg->sql_host, equality);
		} else if (_EQ(line_buf, "sql_database")) {
			_COPY(cfg->sql_database, equality);
		} else if (_EQ(line_buf, "sql_user")) {
			_COPY(cfg->sql_user, equality);
		} else if (_EQ(line_buf, "sql_pass")) {
			_COPY(cfg->sql_pass, equality);

		/* LDAP Configuration */
		} else if (_EQ(line_buf, "ldap_host")) {
			_COPY(cfg->ldap_host, equality);
		} else if (_EQ(line_buf, "ldap_user")) {
			_COPY(cfg->ldap_user, equality);
		} else if (_EQ(line_buf, "ldap_pass")) {
			_COPY(cfg->ldap_pass, equality);
		} else if (_EQ(line_buf, "ldap_dn")) {
			_COPY(cfg->ldap_dn, equality);

		/* Parsing PAM configuration */
		} else if (_EQ(line_buf, "pam_enforce")) {
			REQUIRE_ED_ARG();
			cfg->pam_enforce = arg;
		} else if (_EQ(line_buf, "pam_enforce_policy")) {
			REQUIRE_ED_ARG();
			cfg->pam_enforce_policy = arg;
		} else if (_EQ(line_buf, "pam_retry")) {
			REQUIRE_INT_ARG(0, 3);
			cfg->pam_retry = arg;
		} else if (_EQ(line_buf, "pam_retries")) {
			REQUIRE_INT_ARG(2, 5);
			cfg->pam_retries = arg;
		} else if (_EQ(line_buf, "pam_logging")) {
			REQUIRE_INT_ARG(0, 3);
			cfg->pam_logging = arg;
		} else if (_EQ(line_buf, "pam_silent")) {
			REQUIRE_ED_ARG();
			cfg->pam_silent = arg;
		} else if (_EQ(line_buf, "pam_oob")) {
			REQUIRE_INT_ARG(0, 3);
			cfg->pam_oob = arg;
		} else if (_EQ(line_buf, "pam_oob_delay")) {
			REQUIRE_INT_ARG(0, 172800);
			cfg->pam_oob_delay = arg;
		} else if (_EQ(line_buf, "pam_oob_user")) {
			struct passwd *pwd;
			pwd = getpwnam(equality);
			if (pwd == NULL) {
				print(PRINT_ERROR,
				      "Config Error at %d: Illegal OOB user specified in config.\n", line_count);
				goto error;
			}
			cfg->pam_oob_uid = pwd->pw_uid;
			cfg->pam_oob_gid = pwd->pw_gid;
			endpwent();
			if (cfg->pam_oob_uid == 0) {
				print(PRINT_ERROR,
				      "Config Error at %d: PAM_OOB_USER variable is set to root.", line_count);
				goto error;
			}

		} else if (_EQ(line_buf, "pam_oob_path")) {
			_COPY(cfg->pam_oob_path, equality);
		} else if (_EQ(line_buf, "pam_key_regeneration_prompt")) {
			REQUIRE_ED_ARG();
			cfg->pam_key_regeneration_prompt = arg;
		} else if (_EQ(line_buf, "pam_failure_warning")) {
			REQUIRE_ED_ARG();
			cfg->pam_failure_warning = arg;
		} else if (_EQ(line_buf, "pam_failure_boundary")) {
			REQUIRE_INT_ARG(0, 500);
			cfg->pam_failure_boundary = arg;
		} else if (_EQ(line_buf, "pam_failure_delay")) {
			REQUIRE_INT_ARG(0, 500);
			cfg->pam_failure_delay = arg;
		} else if (_EQ(line_buf, "pam_spass_require")) {
			REQUIRE_ED_ARG();
			cfg->pam_spass_require = arg;

		/* Parsing POLICY configuration */
		} else if (_EQ(line_buf, "key_generation")) {
			REQUIRE_DAE_ARG(0);
			cfg->key_generation = arg;
		} else if (_EQ(line_buf, "key_regeneration")) {
			REQUIRE_DAE_ARG(0);
			cfg->key_regeneration = arg;
		} else if (_EQ(line_buf, "disabling")) {
			REQUIRE_DAE_ARG(0);
			cfg->disabling = arg;
		} else if (_EQ(line_buf, "sourced_key_generation")) {
			REQUIRE_DAE_ARG(0);
			cfg->sourced_key_generation = arg;
		} else if (_EQ(line_buf, "key_removal")) {
			REQUIRE_DAE_ARG(0);
			cfg->key_removal = arg;
		} else if (_EQ(line_buf, "skipping")) {
			REQUIRE_DAE_ARG(0);
			cfg->skipping = arg;
		} else if (_EQ(line_buf, "backward_skipping")) {
			print(PRINT_ERROR,
			      "Config Error at %d: Backward skipping policy was removed. This is now strictly prohibited.\n", line_count);
			goto error;
		} else if (_EQ(line_buf, "verbose_output")) {
			print(PRINT_ERROR,
			      "Config Error at %d: VERBOSE_OUTPUT option removed. Currently is meaningless.\n", line_count);
			goto error;
		} else if (_EQ(line_buf, "shell_auth")) {
			REQUIRE_DAE_ARG(0);
			cfg->shell_auth = arg;
		} else if (_EQ(line_buf, "passcode_print")) {
			REQUIRE_DAE_ARG(0);
			cfg->passcode_print = arg;
		} else if (_EQ(line_buf, "key_print")) {
			REQUIRE_DAE_ARG(0);
			cfg->key_print = arg;

		} else if (_EQ(line_buf, "salt")) {
			REQUIRE_DAE_ARG(1);
			cfg->salt = arg;
		} else if (_EQ(line_buf, "salt_def")) {
			REQUIRE_ED_ARG();
			cfg->salt_def = arg;

		} else if (_EQ(line_buf, "show")) {
			REQUIRE_DAE_ARG(1);
			cfg->show = arg;
		} else if (_EQ(line_buf, "show_def")) {
			REQUIRE_ED_ARG();
			cfg->show_def = arg;

		} else if (_EQ(line_buf, "state_import")) {
			REQUIRE_DAE_ARG(0);
			cfg->state_import = arg;
		} else if (_EQ(line_buf, "state_export")) {
			REQUIRE_DAE_ARG(0);
			cfg->state_export = arg;
		} else if (_EQ(line_buf, "contact_change")) {
			REQUIRE_DAE_ARG(0);
			cfg->contact_change = arg;
		} else if (_EQ(line_buf, "label_change")) {
			REQUIRE_DAE_ARG(0);
			cfg->label_change = arg;

		} else if (_EQ(line_buf, "passcode_def_length")) {
			REQUIRE_INT_ARG(2, 16);
			cfg->passcode_def_length = arg;
		} else if (_EQ(line_buf, "passcode_min_length")) {
			REQUIRE_INT_ARG(2, 16);
			cfg->passcode_min_length = arg;
		} else if (_EQ(line_buf, "passcode_max_length")) {
			REQUIRE_INT_ARG(2, 16);
			cfg->passcode_max_length = arg;

		} else if (_EQ(line_buf, "alphabet_change")) {
			REQUIRE_DAE_ARG(0);
			cfg->alphabet_change = arg;
		} else if (_EQ(line_buf, "alphabet_def")) {
			REQUIRE_INT_ARG(1, 2);
			cfg->alphabet_def = arg;
		} else if (_EQ(line_buf, "alphabet_min_length")) {
			REQUIRE_INT_ARG(5, 88);
			cfg->alphabet_min_length = arg;
		} else if (_EQ(line_buf, "alphabet_max_length")) {
			REQUIRE_INT_ARG(5, 88);
			cfg->alphabet_max_length = arg;
		} else if (_EQ(line_buf, "alphabet_custom")) {
			if (_alphabet_check(equality) != 0) {
				goto error;
			}
			_COPY(cfg->alphabet_custom, equality);

		} else if (_EQ(line_buf, "spass_change")) {
			REQUIRE_DAE_ARG(0);
			cfg->spass_change = arg;
		} else if (_EQ(line_buf, "spass_min_length")) {
			REQUIRE_INT_ARG(4, 500);
			cfg->spass_min_length = arg;
		} else if (_EQ(line_buf, "spass_require_digit")) {
			REQUIRE_INT_ARG(0, 20);
			cfg->spass_require_digit = arg;
		} else if (_EQ(line_buf, "spass_require_special")) {
			REQUIRE_INT_ARG(0, 20);
			cfg->spass_require_special = arg;
		} else if (_EQ(line_buf, "spass_require_uppercase")) {
			REQUIRE_INT_ARG(0, 20);
			cfg->spass_require_uppercase = arg;

		} else {
			/* Error */
			print(PRINT_ERROR, "Unrecognized variable '%s' on line %d in config file\n",
			      line_buf, line_count);
			fail++;
		}

	} while (!feof(f));

	retval = 2;
	if (cfg->show == CONFIG_DISALLOW) {
		if (cfg->show_def == CONFIG_ENABLED) {
			print(PRINT_ERROR, "Config error: Default for SHOW inconsistent with policy.\n");
			goto error;
		}
	}

	if (cfg->show == CONFIG_ENFORCE) {
		if (cfg->show_def == CONFIG_DISABLED) {
			print(PRINT_ERROR, "Config error: Default for SHOW inconsistent with policy.\n");
			goto error;
		}
	}

	if (cfg->salt == CONFIG_DISALLOW) {
		if (cfg->salt_def == CONFIG_ENABLED) {
			print(PRINT_ERROR, "Config error: Default for SALT inconsistent with policy.\n");
			goto error;
		}
	}

	if (cfg->salt == CONFIG_ENFORCE) {
		if (cfg->salt_def == CONFIG_DISABLED) {
			print(PRINT_ERROR, "Config error: Default for SALT inconsistent with policy.\n");
			goto error;
		}
	}

	if (cfg->passcode_def_length > cfg->passcode_max_length ||
	    cfg->passcode_def_length < cfg->passcode_min_length) {
		print(PRINT_ERROR, "Config error: Default passcode length "
		      "inconsistent with policy.\n");
		goto error;
	}

	/* TODO/FIXME: Check if config readable by others and 
	 * DB=mysql/ldap */

	/* All ok? */
	if (fail)
		retval = 1;
	else {
		retval = 0;
		if (cfg->db == CONFIG_DB_UNCONFIGURED) 
			retval = 5;
	}
error:
	fclose(f);
	return retval;
}

static int _config_init(cfg_t *cfg, const char *config_path)
{
	int retval;
	_config_defaults(cfg);
	retval = _config_parse(cfg, config_path);

	if (retval != 0) {
		_config_defaults(cfg);
	}

	return retval;
}

cfg_t *cfg_get(void)
{
	/* Here is stored our global structure */
	static cfg_t cfg;
	static cfg_t *cfg_init = NULL;

	int retval;

	if (cfg_init)
		return cfg_init;

	retval = _config_init(&cfg, CONFIG_PATH);
	if (retval != 0 && retval != 5)
		return NULL;

	cfg_init = &cfg;

	return cfg_init;
}

int cfg_permissions(void)
{
	struct stat st;
	if (stat(CONFIG_PATH, &st) != 0) {
		print(PRINT_ERROR, "Unable to check config file permissions\n");
		return PPP_ERROR;
	}

	if (st.st_uid != 0 || st.st_gid != 0) {
		return PPP_ERROR_CONFIG_OWNERSHIP;
	}

	cfg_t *cfg = cfg_get();
	assert(cfg);

	switch (cfg->db) {
	case CONFIG_DB_MYSQL:
	case CONFIG_DB_LDAP:
		if (st.st_mode & (S_IRWXO)) {
			return PPP_ERROR_CONFIG_PERMISSIONS;
		}
	default:
		break;
	}

	return 0;
}
