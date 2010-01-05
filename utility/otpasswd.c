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
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h> /* chdir, environ */

#include "security.h"

#define PPP_INTERNAL
#include "ppp.h"

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "config.h"

#include "passcards.h"


#include "otpasswd_actions.h"
#include "testcases.h"

static const char *_program_name(const char *argv0)
{
	const char *pos;
	if (!argv0)
		return "otpasswd";

	pos = strrchr(argv0, '/');
	if (pos)
		return pos+1;
	else
		return argv0;
}

static void _usage(int argc, const char **argv)
{
	const char *prog_name =	_program_name(argc >= 2 ? argv[0] : NULL);
	fprintf(stdout,
		"Usage: %s [options]\n"
		"Actions:\n"
		"  -k, --key\n"
		"           Generate a new key. You can pass\n"
		"           -d, -c and -f options along.\n"
		"  -r, --remove\n"
		"           Remove key, and disable OTP.\n"
		"\n"
		"  -s, --skip <which>\n"
		"           Skip to a card specified as an argument.\n"
		"  -t, --text <which>\n"
		"           Generate either one ascii passcard\n"
		"           or a single passcode depending on argument. \n"
		"  -l, --latex <which>\n"
		"           Generate a LaTeX output with 6 passcards\n"
		"           starting with the specified one\n"
		"  -a, --authenticate <passcode>\n"
		"           Try to authenticate with given passcode\n"
		"  -w, --warning\n"
		"           Display warnings (ex. user on last passcard)\n"
		"  -P, --prompt <which>\n"
		"           Display authentication prompt for given passcode\n"
		"\n"
		"Where <which> might be one of:\n"
		"  number         - a decimal number of a passcode\n"
		"  [number]       - a passcard number\n"
		"  CRR[number]    - a passcode in passcard of a given number.\n"
		"                   C is column (A through G), RR - row (1..10)\n"
		"  current        - passcode used for next time authentication\n"
		"  [current]      - passcard containing current passcode\n"
		"  next or [next] - first, not yet printed, passcard\n"
		"\n"
		"Configuration:\n"
		"  -f, --flag <arg>\n"
		"           Manages various settings:\n"
		"           list          print current state and configuration.\n"
		"           show=<on|off> configure visibility of passcode during\n"
		"                         authentication.\n"
		"           alphabet=<ID|list>\n"
		"                         select passcode alphabet. Use 'list' argument\n"
		"                         to get IDs of available alphabets.\n"
		"           codelenght=<length>\n"
		"                         select passcode length.\n"
		"\n"
		"           contact=X     Set contact info (e.g. phone number) with\n"
		"                         which to receive a passcode during authentication.\n"
		"                         Details depends configuration. Use \"\" to disable.\n"

		"           label=X       Set a caption to use on generated passcards.\n"
	        "                         Use \"\" to set default (hostname)\n"
		"\n"
		"           salt=<on|off>\n"
		"                         Meaningful only during key generation.\n"
		"                         Enable/disable salting of a passcode counter.\n"
		"                         Disabling this option will make program\n"
		"                         compatible with PPPv3.1 and will increase\n"
		"                         available passcard number at the cost of\n"
		"                         (theoretically) less security.\n"
		"\n"
		"           disable=<on|off>\n"
		"                         Disable user without removing his data.\n"
		"\n"
		"  -p, --password <pass>\n"
		"           Set static password. Use empty (i.e. "") to unset.\n"
		"\n"
		"  -u, --user <username|UID>\n"
		"           Operate on state of specified user. Administrator-only option.\n"
		"  -v, --verbose\n"
		"           Display more information about what is happening.\n"
		"  --version\n"
		"           Display license, warranty, version and author information.\n"
		"  -h, --help\n"
		"           Display this message\n"
		"  --check  Run all testcases. Assumes default config file.\n"

		"\n"
		"Notes:\n"
		"  Both --text and --latex can get \"next\" as a parameter which\n"
		"  will print the first not-yet printed passcard. Usage of this argument\n"
		"  is recommended as it enables OTPasswd to display warnings when user\n"
		"  reaches his last printed passcard.\n"
		"\nExamples:\n"
		"%s -f salt=off --key    generate new (not salted) key\n"
		"%s --text '[3]'         print third passcard to standard output\n"
		"%s --text current       print current passcode\n"
		"%s --flag codelength=5  use 5-character long passcodes\n"
		"Generate a 6 passcards on A4 page using LaTeX:\n"
		"%s --latex next > tmp.latex\n"
		"pdflatex tmp.latex\n",
		prog_name, prog_name, prog_name, prog_name, prog_name, prog_name
	);
}

/* Parsing is done here, policy checking in _update_flags */
int parse_flag(options_t *options, const char *arg)
{
	const cfg_t *cfg = cfg_get();
	assert(cfg);
	assert(arg);

	/*** Booleans/specials support ***/
	if (strcmp(arg, "show=on") == 0)
		options->flag_set_mask |= FLAG_SHOW;
	else if (strcmp(arg, "show=off") == 0)
		options->flag_clear_mask |= FLAG_SHOW;
	else if (strcmp(arg, "salt=on") == 0)
		options->flag_set_mask |= FLAG_SALTED;
	else if (strcmp(arg, "salt=off") == 0)
		options->flag_clear_mask |= FLAG_SALTED;
	else if (strcmp(arg, "disable=off") == 0)
		options->flag_clear_mask |= FLAG_DISABLED;
	else if (strcmp(arg, "disable=on") == 0)
		options->flag_set_mask |= FLAG_DISABLED;
	else if (strcmp(arg, "list") == 0) {
		if (options->action != OPTION_FLAGS) {
			printf("Only one action can be specified on the command line\n"
			       "and you can't mix \"list\" flag with other flags.\n");
			return 1;
		}

		/* List! Instead of changing flags. */
		options->action = OPTION_SHOW_STATE;
	} else if (strcmp(arg, "alphabet=list") == 0) {
		if (options->action != OPTION_FLAGS) {
			printf("Only one action can be specified on the command line\n"
			       "and you can't mix alphabet listing with other flags.\n");
			return 1;
		}
		options->action = OPTION_ALPHABETS; /* List alphabets instead of changing flags */

		/*** Label and contact support */
	} else if (strncmp(arg, "contact=", 8) == 0) {
		const char *contact = arg + 8;

		if (options->contact) {
			printf("Contact already defined\n");
			return 1;
		}

		/* Store */
		options->contact = strdup(contact);
	} else if (strncmp(arg, "label=", 6) == 0) {
		const char *label = arg + 6;

		if (options->label) {
			printf("Label already defined\n");
			return 1;
		}

		/* Store */
		options->label = strdup(label);

		/*** Integer argument support */
	} else {
		int tmp;
		if (sscanf(arg, "codelength=%d", &tmp) == 1) {
			if (tmp == -1)    /* Also illegal, but we use */
				tmp = -2; /* -1 to mark it's not set */

			options->set_codelength = tmp;
		} else if (sscanf(arg, "alphabet=%d", &tmp) == 1) {
			if (tmp == -1)    /* Also illegal, but we use */
				tmp = -2; /* -1 to mark it's not set */

			options->set_alphabet = tmp;
		} else {
			/* Illegal flag */
			printf("No such flag or illegal option (%s).\n", arg);
			return 1;
		}
	}

	/* Verify user don't want to unset and set at the same time */
	if (options->flag_set_mask & options->flag_clear_mask) {
		printf("Illegal set of flags defined.\n");
		return 1;
	}


	return 0;
}

/* Parse command line. Ensure we do not put any wrong data into options,
 * that is - longer than expected or containing any illegal characters */
int process_cmd_line(int argc, char **argv, options_t *options, cfg_t *cfg)
{
	assert(cfg);
	assert(options);

	/* This will cause GMP to free memory safely */
	num_init();

	/* By default perform only some logging */
	cfg->logging = 1;

	static struct option long_options[] = {
		/* Action selection */
		{"key",			no_argument,		0, OPTION_KEY},
		{"remove",		no_argument,		0, OPTION_REMOVE},
		{"skip",		required_argument,	0, OPTION_SKIP},
		{"text",		required_argument,	0, OPTION_TEXT},
		{"latex",		required_argument,	0, OPTION_LATEX},
		{"prompt",		required_argument,	0, OPTION_PROMPT},
		{"authenticate",	required_argument,	0, OPTION_AUTH},
		{"warning",		no_argument,		0, OPTION_WARN},

		/* Flags */
		{"flags",		required_argument,	0, OPTION_FLAGS},
		{"password",		required_argument,	0, OPTION_SPASS},
		{"user",		required_argument,	0, OPTION_USER},
		{"verbose",		no_argument,		0, OPTION_VERBOSE},
		{"check",		no_argument,		0, OPTION_CHECK},
		{"version",		no_argument,		0, OPTION_VERSION},
		{"help",		no_argument,		0, OPTION_HELP},

		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

/* FIXME: Remove this old entry */
/*	int c = getopt_long(argc, argv, "krs:t:l:P:a:wf:p:d:c:vu:h", long_options, &option_index); */
		int c = getopt_long(argc, argv, "krs:t:l:P:a:wf:p:vu:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1) {
			if (optind < argc) {
				printf("Garbage on command line. (%s)\n", argv[optind]);
				goto error;
			}

			break;
		}

		/* Assert maximal length of parameter */
		if (optarg && (strlen(optarg) > 100)) {
			printf("Option argument too long!\n");
			goto error;
		}

		switch (c) {
			/* Argument-less actions */
		case OPTION_VERSION:
		case OPTION_WARN:
		case OPTION_KEY:
		case OPTION_REMOVE:
		case OPTION_CHECK:
		case OPTION_HELP:
			/* Error unless there was flag defined for key generation */
			if (options->action != 0 && (
				    options->action != OPTION_FLAGS 
				    && c != OPTION_KEY
			)) {
				printf("Only one action can be specified on the command line\n");
				return 1;
			}
			options->action = c;
			break;

			/* Actions with argument */
		case OPTION_SKIP:
		case OPTION_TEXT:
		case OPTION_LATEX:
		case OPTION_PROMPT:
		case OPTION_AUTH:
		case OPTION_SPASS:
			if (options->action != 0) {
				printf("Only one action can be specified on the command line\n");
				goto error;
			}
			options->action = c;

			if (optarg)
				options->action_arg = strdup(optarg);
			else
				options->action_arg = NULL;
			break;

			/* Actions with argument which can be connected with -k */
		case OPTION_FLAGS:
			if (options->action != 0 && 
			    options->action != OPTION_FLAGS &&
			    options->action != OPTION_KEY) {
				printf("Only one action can be specified on the command line\n");
				goto error;
			}

			if (options->action == 0)
				options->action = OPTION_FLAGS;

			assert(optarg != NULL);

			if (parse_flag(options, optarg) != 0)
				goto error;

			break;

		case '?':
			/* getopt_long already printed an error message. */
			_usage(argc, (const char **)argv);
			goto error;

		case OPTION_USER:
			assert(optarg);
			if (security_is_root() == 0) {
				printf("Only root can use the '--user' option\n");
				exit(EXIT_SUCCESS);
			}

			if (options->username) {
				printf("Multiple '--user' options passed\n");
				exit(EXIT_SUCCESS);
			}

			options->username = security_parse_user(optarg);
			if (!options->username) {
				printf("Illegal user specified on command prompt\n");
				exit(EXIT_SUCCESS);
			}
			break;

		case OPTION_VERBOSE:
			if (!security_is_root() && cfg->allow_verbose_output == 0) {
				printf("Verbose output denied by policy.\n");
				goto error;
			}

			cfg->logging = 2;
			break;

		default:
			printf("Got %d %c\n", c, c);
			assert(0);
		}
	}

	/* Check additional correctness */
	if (((options->flag_set_mask | options->flag_clear_mask) & FLAG_SALTED)
	    && (options->action != 'k')) {
		printf("The \"salt\" flag can only be specified during key creation!\n");
		goto error;
	}

	if (!options->username) {
		/* User not specified, use the one who has ran us */
		options->username = security_get_current_user();
		if (!options->username) {
			printf("Unable to determine name of current user!\n");
			goto error;
		}
	}

	return 0;

error:
	free(options->username);
	free(options->action_arg);
	return 1;
}

int perform_action(int argc, char **argv, options_t *options, cfg_t *cfg)
{
	int ret;
	int retval;

	/* Initialize logging subsystem */
	if (print_init(cfg->logging == 1 ? PRINT_WARN : PRINT_NOTICE,
		       1, 0, NULL) != 0) {
		printf("Unable to start debugging\n");
	}


	/* Perform action */
	switch (options->action) {
	case 0:
		print(PRINT_ERROR, "No action specified. Try passing -k, -s, -t or -l\n\n");
		_usage(argc, (const char **) argv);
		retval = 1;
		goto cleanup;

	case OPTION_HELP:
		_usage(argc, (const char **)argv);
		retval = 0;
		break;

	case OPTION_KEY:
	case OPTION_REMOVE:
		retval = action_key(options, cfg);
		break;

	case OPTION_SHOW_STATE: 
	case OPTION_ALPHABETS:
	case OPTION_FLAGS:
	case OPTION_SPASS:
		retval = action_flags(options, cfg);
		break;

	case OPTION_AUTH:
		ret = action_authenticate(options, cfg);
		print_fini();
		if (ret == 0)
			retval = 1;
		break;
	case OPTION_VERSION:
		retval = action_license(options, cfg);
		break;

	case OPTION_WARN:
	case OPTION_SKIP:
	case OPTION_TEXT:
	case OPTION_LATEX:
	case OPTION_PROMPT:
		retval = action_print(options, cfg);
		break;

	case OPTION_CHECK:
		printf("*** Running testcases\n");
		{
			int failed = 0;

			/* Change DB info so we won't overwrite anything
			 * important */
			strcpy(cfg->user_db_path, ".otpasswd_testcase");
			strcpy(cfg->global_db_path, "/tmp/otshadow_testcase");
			cfg->db = CONFIG_DB_USER;

			failed += config_testcase();
			failed += state_testcase();
			failed += num_testcase();
			failed += crypto_testcase();
			failed += card_testcase();
			failed += ppp_testcase();
			if (failed) {
				printf(
					"***********************************************\n"
					"*         !!! %d testcases failed !!!         *\n"
					"* Don't use this release until this is fixed! *\n"
					"* Note: Testcases should be run with default  *\n"
					"* If unsure, reinstall and rerun --check      *\n"
					"***********************************************\n",
					failed);
				retval = 1;
			} else {
				printf(
					"**********************************\n"
					"* All testcases seem successful. *\n"
					"**********************************\n");
				retval = 0;
			}
		}
	}


cleanup:
	free(options->action_arg);
	free(options->label);
	free(options->contact);
	free(options->username);
	print_fini();
	return retval;
}

extern char **environ;
int main(int argc, char **argv)
{
	int ret;
	cfg_t *cfg = NULL;

	/* Options passed to utility with command line */
	options_t options = {
		.action = 0,
		.action_arg = NULL,
		.label = NULL,
		.contact = NULL,

		.username = NULL,

		.flag_set_mask = 0,
		.flag_clear_mask = 0,
		.set_codelength = -1,
		.set_alphabet = -1,
	};

	/* Init environment, store uids, etc. */
	security_init();

	/* Bootstrap logging subsystem. */
	if (print_init(PRINT_WARN, 1, 0, NULL) != 0) {
		printf("ERROR: Unable to start log subsystem\n");
		exit(EXIT_FAILURE);
	}

	/* TODO:
	 * If we are SUID and DB=LDAP or DB=MySQL ensure only
	 * we can read config.
	 */

	/* Get global config */
	cfg = cfg_get();


	if (!cfg) {
		printf("\nUnable to read config file from %s\n", CONFIG_PATH);
		printf("OTPasswd not correctly installed, consult installation manuals.\n");
		printf("Consult installation manual for detailed information.\n");
		print_fini();
		exit(EXIT_FAILURE);
	}

	/* If DB is global, mysql or ldap we should be SGID/SUID */
	if (cfg->db != CONFIG_DB_USER &&
	    security_privileged(1, 1) == 0) {
		/* Something is wrong. We are not SGID nor SUID.
		 * Or we're run as SUID user which is also bad.
		 */
		print(PRINT_WARN, "Database type set to global/MySQL/LDAP, yet program "
		       "is not a SUID or is incorrectly ran by it's owner.\n");
	}

	print_fini();

	/* Config is read. We know LDAP/MySQL passwords and
	 * if DB is not global we must drop permissions now
	 * as our SUID user might not be able to read state
	 * file from user directory
	 *
	 *
	 * FIXME: Can signal from user while connecting to LDAP/MySQL
	 * cause problems?
	 */
	if (cfg->db != CONFIG_DB_GLOBAL) {
		security_permanent_drop();

		/* After drop we can safely parse user data */
		ret = process_cmd_line(argc, argv, &options, cfg);
	} else {
		/* Ensure our SUID matches config */
		security_ensure_user(cfg->user_uid, cfg->user_gid);

		/* Before we gain pernamently permissions,
		 * drop them temporarily and parse user data */
		security_temporal_drop();
		ret = process_cmd_line(argc, argv, &options, cfg);


		/* Otherwise - switch pernamently to SUID user
		 * so the user can't send us any signals while we
		 * have state files locked */
		security_permanent_switch();


	}


	if (ret != 0)
		return ret;


	ret = perform_action(argc, argv, &options, cfg);
	return ret;
}
