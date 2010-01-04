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

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "config.h"

#include "passcards.h"

#define PPP_INTERNAL
#include "ppp.h"

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
		"  -k, --key    Generate a new key. You can pass\n"
		"               -d, -c and -f options along.\n"
		"  -r, --remove Remove key, and disable OTP for user.\n"
		"\n"
		"  -s, --skip <which>\n"
		"               Skip to a card specified as an argument.\n"
		"  -t, --text <which>\n"
		"               Generate either one ascii passcard\n"
		"               or a single passcode depending on argument. \n"
		"  -l, --latex <which>\n"
		"               Generate a LaTeX output with 6 passcards\n"
		"               starting with the specified one\n"
		"  -a, --authenticate <passcode>\n"
		"               Try to authenticate with given passcode\n"
		"  -P, --prompt <which>\n"
		"               Display authentication prompt for given passcode\n"
		"  -w, --warning\n"
		"               Display warnings (ex. user on last passcard)\n"
		"\n"
		"Where <which> might be one of:\n"
		"  number         - a decimal number of a passcode\n"
		"  [number]       - a passcard number\n"
		"  CRR[number]    - a passcode in passcard of a given number.\n"
		"                   C is column (A through G), RR - row (1..10)\n"
		"  current        - passcode used for next time authentication\n"
		"  [current]      - passcard containing current passcode\n"
		"  next or [next] - first, not yet printed, passcard\n"

		"\nConfiguration:\n"
		"  -f, --flag <arg>\n"
		"               Manages various user-selectable flags:\n"
		"               list              print current state data\n"
		"               show              show passcode while authenticating (default)\n"
		"               dont-show         do not show passcode\n"
		"               alphabet-X        sets used alphabet, X can be an ID or\n"
		"                                 a 'list' command, which will print\n"
		"                                 IDs of all available alphabets.\n"
		"               codelenght-X      sets passcodes length, X is a number\n"
		"                                 from 2 to 16 (default: codelength-4)\n"

		"\n"
		"               no-salt           Meaningful only during key generation.\n" 
		"                                 Disables salting of a passcode counter.\n"
		"                                 Enabling this option will make program\n"
		"                                 compatible with PPPv3.1 and will increase\n"
		"                                 available passcard number at the cost of\n"
		"                                 (theoretically) less security.\n"
		"               salt              Enables salting of key if not enabled\n"
		"                                 by default.\n"
		"\n"
		"  -p, --password <pass>\n"
		"               Set static password. Use empty (i.e. "") to unset.\n"
		"  -c, --contact <arg>\n"
		"               Set a contact info (e.g. phone number) with which\n"
		"               you want to receive current passcode during authentication.\n"
		"               Details depends on pam module configuration. Use \"\"\n"
		"               to disable.\n"
		"  -d, --label <arg>\n"
		"               Set a caption to use on generated passcards.\n"
		"               Use \"\" to set default (hostname)\n"
		"\n"
		"  -u, --user <username|UID>\n"
		"                Operate on state of specified user. Administrator-only option.\n"
		"  -v, --verbose Display more information about what is happening.\n"
		"  --version     Display license, warranty, version and author information.\n"
		"  -h, --help    This message\n"
		"  --check       Run all testcases. Assumes default config file.\n"


		"\nNotes:\n"
		"  Both --text and --latex can get \"next\" as a parameter which\n"
		"  will print the first not-yet printed passcard\n"
		"\nExamples:\n"
		"%s --key                generate new (salted) key\n"
		"%s --text '[3]'         print third passcard to standard output\n"
		"%s --text current       print current passcode\n"
		"%s --flag codelength-5  use 5-character long passcodes\n"
		"Generate a 6 passcards on A4 page using LaTeX:\n"
		"%s --latex next > tmp.latex\n"
		"pdflatex tmp.latex\n",
		prog_name, prog_name, prog_name, prog_name, prog_name, prog_name
	);
}


int parse_flag(options_t *options, const char *arg)
{
	const cfg_t *cfg = cfg_get();
	assert(cfg);
	
	if (strcmp(arg, "show") == 0)
		options->flag_set_mask |= FLAG_SHOW;
	else if (strcmp(arg, "dont-show") == 0)
		options->flag_clear_mask |= FLAG_SHOW;
	else if (strcmp(arg, "salt") == 0)
		options->flag_set_mask |= FLAG_SALTED;
	else if (strcmp(arg, "no-salt") == 0)
		options->flag_clear_mask |= FLAG_SALTED;
	else if (strcmp(arg, "list") == 0) {
		if (options->action != 'f') {
			printf("Only one action can be specified on the command line\n"
			       "and you can't mix 'list' flag with other flags.\n");
			return 1;
		}
		
		options->action = 'L'; /* List! Instead of changing flags. */
	} else if (strcmp(arg, "alphabet-list") == 0) {
		if (options->action != 'f') {
			printf("Only one action can be specified on the command line\n"
			       "and you can't mix 'list' flag with other flags.\n");
			return 1;
		}
		options->action = 'A'; /* List alphabets instead of changing flags */
	} else {
		int tmp;
		if (sscanf(arg, "codelength-%d", &tmp) == 1) {
			if (tmp < 2 || tmp > 16) {
				printf("Passcode length must be between 2 and 16.\n");
				return 1;
			}

			if (tmp < cfg->passcode_min_length ||
			    tmp > cfg->passcode_max_length) {
				printf("Passcode length denied by policy.\n");
				return 1;
				
			}
			options->set_codelength = tmp;

		} else if (sscanf(arg, "alphabet-%d", &tmp) == 1) {
			const int ret = ppp_alphabet_verify(tmp);
			if (ret == 1) {
				printf("Illegal alphabet specified. See "
				       "-f alphabet-list\n");
				return 1;
			} else if (ret == 2) {
				printf("Alphabet denied by policy. See "
				       "-f alphabet-list\n");
				return 2;
			} else if (ret != 0) 
				return 3;

			options->set_alphabet = tmp;

		} else {
			/* Illegal flag */
			printf("No such flag %s\n", arg);
			return 1;
		}
	}
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
		{"key",			no_argument,		0, 'k'},
		{"remove",		no_argument,		0, 'r'},
		{"skip",		required_argument,	0, 's'},
		{"text",		required_argument,	0, 't'},
		{"latex",		required_argument,	0, 'l'},
		{"prompt",		required_argument,	0, 'P'},
		{"authenticate",	required_argument,	0, 'a'},
		{"warning",		no_argument,		0, 'w'},

		/* Flags */
		{"flags",		required_argument,	0, 'f'},
		{"password",		required_argument,	0, 'p'},
		{"label",		required_argument,	0, 'd'},
		{"contact",		required_argument,	0, 'c'},
		{"no-salt",		no_argument,		0, 'n'},
		{"user",		required_argument,	0, 'u'},
		{"verbose",		no_argument,		0, 'v'},
		{"check",		no_argument,		0, 'x'},
		{"version",		no_argument,		0, 'Q'},
		{"help",		no_argument,		0, 'h'},

		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "krs:t:l:P:a:wf:p:d:c:vu:h", long_options, &option_index);

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
		case 'Q':
		case 'w':
		case 'k':
		case 'r':
		case 'x':
		case 'h':
			/* Error unless there was flag defined for key generation */
			if (options->action != 0 && (options->action != 'f' && c != 'k')) {
				printf("Only one action can be specified on the command line\n");
				return 1;
			}
			options->action = c;
			break;

			/* Actions with argument */
		case 's':
		case 't':
		case 'l':
		case 'P':
		case 'a':
		case 'p':

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
		case 'd':
		case 'c':
			if (options->action == 0) {
				options->action = 'f';
			} else if (options->action == 'k') {
				/* Don't change action */
			} else if (options->action == 'f') {
				/* Keep 'f' if -d or -c not given already */
			} else {
				printf("Only one action can be specified on the command line\n");
				goto error;
			}

			assert(optarg);
			
			/* Check data correctness */
			if (!state_validate_str(optarg)) {
				printf(
					"%s argument contains illegal characters.\n"
					"Alphanumeric + ' -+,.@_*' are allowed\n",
					c=='d' ? "Label" : "Contact");
				goto error;
			}

			switch (c) {
			case 'c':
				if (options->contact) {
					printf("Contact already defined\n");
					goto error;
				}

				if (!security_is_root() && cfg->allow_contact_change == 0) {
					printf("Contact changing denied by policy.\n");
					goto error;
				}

				if (strlen(optarg) + 1 > STATE_CONTACT_SIZE) {
					printf("Contact can't be longer than %d "
					       "characters\n", STATE_CONTACT_SIZE-1);
					goto error;
				}

				/* Store */
				options->contact = strdup(optarg);
				break;

			case 'd':
				if (options->label) {
					printf("Label already defined\n");
					goto error;
				}

				if (!security_is_root() && cfg->allow_label_change == 0) {
					printf("Contact changing denied by policy.\n");
					goto error;
				}

				if (strlen(optarg) + 1 > STATE_LABEL_SIZE) {
					printf("Label can't be longer than %d "
					       "characters\n", STATE_LABEL_SIZE-1);
					goto error;
				}

				/* Store */
				options->label = strdup(optarg);
				break;
			default:
				assert(0);
			}

			break;

		case 'f':
			if (options->action != 0 && options->action != 'f' && options->action != 'k') {
				printf("Only one action can be specified on the command line\n");
				goto error;
			}

			if (options->action == 0)
				options->action = 'f';

			assert(optarg != NULL);

			if (parse_flag(options, optarg) != 0)
				goto error;

			break;

		case '?':
			/* getopt_long already printed an error message. */
			_usage(argc, (const char **)argv);
			goto error;

		case 'u':
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

		case 'v':
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
		printf("salt or no-salt flag can only be specified during key creation!\n");
		goto error;
	}

	if (!options->username) {
		/* User not specified, use the one who has ran us */
		options->username = security_get_current_user();
		if (!options->username) {
			printf("Unable to determine current username!\n");
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

	case 'h':
		_usage(argc, (const char **)argv);
		retval = 0;
		break;

	case 'k':
	case 'r':
		retval = action_key(options, cfg);
		break;

	case 'L': /* list action */
	case 'A': /* alphabets list */
	case 'f':
	case 'p':
		retval = action_flags(options, cfg);
		break;

	case 'a':
		ret = action_authenticate(options, cfg);
		print_fini();
		if (ret == 0)
			retval = 1;
		break;
	case 'Q':
		retval = action_license(options, cfg);
		break;

	case 'w': /* Warning */
	case 's':
	case 't':
	case 'l':
	case 'P':
		retval = action_print(options, cfg);
		break;

	case 'x':
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
		printf("Unable to read config file from %s\n", CONFIG_PATH);
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
