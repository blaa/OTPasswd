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

/* OTP Agent */
#include "agent_interface.h"

/* libotp header */
#include "ppp.h"

/* Utility headers */
#include "security.h"
#include "nls.h"
#include "actions.h"
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
	fprintf(stdout, _(
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
	        "  -i, --info\n"
	        "           Print current configuration and state.\n"
	        "      --info-key\n"
	        "           Print key and counter used for generating passcodes.\n"
		"  -c, --config <arg>\n"
		"           Manages various settings:\n"
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
		"  -p, --password\n"
		"           Set static password.\n"
		"  -u, --user <username|UID>\n"
		"           Operate on state of specified user. Administrator-only option.\n"
		"  -v, --verbose\n"
		"           Display more information about what is happening.\n"
		"  --version\n"
		"           Display license, warranty, version and author information.\n"
		"  -h, --help\n"
		"           Display this message\n"
		"  --check  Run all testcases. WARNING: Requires default config file.\n"

		"\n"
		"Notes:\n"
		"  Both --text and --latex can get \"next\" as a parameter which\n"
		"  will print the first not-yet printed passcard. Usage of this argument\n"
		"  is recommended as it enables OTPasswd to display warnings when user\n"
		"  reaches his last printed passcard.\n"
		"\nExamples:\n"
		"%s --config salt=off --key   generate new (not salted) key\n"
		"%s --text next               print first not-yet-printed passcard\n"
		"%s --text '[3]'              print third passcard to standard output\n"
		"%s --text current            print current passcode\n"
		"%s --config codelength=5     use 5-character long passcodes\n"
		"Generate a 6 passcards on A4 page using LaTeX:\n"
		"%s --latex next > tmp.latex\n"
		"pdflatex tmp.latex\n"),
	        prog_name, prog_name, prog_name, prog_name, prog_name, prog_name, prog_name
	);
}

/* Parsing is done here, policy checking in _update_flags */
int parse_flag(options_t *options, const char *arg)
{
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
	else if (strcmp(arg, "alphabet=list") == 0) {
		if (options->action != OPTION_CONFIG) {
			printf(_("Only one action can be specified on the command line\n"
			         "and you can't mix alphabet listing with other flags.\n"));
			return 1;
		}
		options->action = OPTION_ALPHABETS; /* List alphabets instead of changing flags */

		/*** Label and contact support */
	} else if (strncmp(arg, "contact=", 8) == 0) {
		const char *contact = arg + 8;

		if (options->contact) {
			printf(_("Contact already defined\n"));
			return 1;
		}

		/* Store */
		options->contact = strdup(contact);
	} else if (strncmp(arg, "label=", 6) == 0) {
		const char *label = arg + 6;

		if (options->label) {
			printf(_("Label already defined\n"));
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
			printf(_("No such flag or illegal option (%s).\n"), arg);
			return 1;
		}
	}

	/* Verify user don't want to unset and set at the same time */
	if (options->flag_set_mask & options->flag_clear_mask) {
		printf(_("Illegal configuration defined.\n"));
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

	/* By default perform only some logging */
	cfg->pam_logging = 1;

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
		{"info",		no_argument,		0, OPTION_INFO},
		{"info-key",		no_argument,		0, OPTION_INFO_KEY},
		{"config",		required_argument,	0, OPTION_CONFIG},
		{"password",		no_argument,		0, OPTION_SPASS},
		{"user",		required_argument,	0, OPTION_USER},
		{"verbose",		no_argument,		0, OPTION_VERBOSE},
		{"check",		no_argument,		0, OPTION_CHECK},
		{"version",		no_argument,		0, OPTION_VERSION},
		{"help",		no_argument,		0, OPTION_HELP},

		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "krs:t:l:P:a:wic:pvu:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1) {
			if (optind < argc) {
				printf(_("Garbage on command line. (%s)\n"), argv[optind]);
				goto error;
			}

			break;
		}

		/* Assert maximal length of parameter */
		if (optarg && (strlen(optarg) > 100)) {
			printf(_("Option argument too long!\n"));
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
		case OPTION_INFO:
		case OPTION_INFO_KEY:
		case OPTION_SPASS:
			/* Error unless there was flag defined for key generation */
			if (options->action != 0 &&
			    !(options->action == OPTION_CONFIG && c == OPTION_KEY)) {
				printf(_("Only one action can be specified on the command line.\n"));
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
			if (options->action != 0) {
				printf(_("Only one action can be specified on the command line.\n"));
				goto error;
			}
			options->action = c;

			if (optarg)
				options->action_arg = strdup(optarg);
			else
				options->action_arg = NULL;
			break;

			/* Actions with argument which can be connected with -k */
		case OPTION_CONFIG:
			if (options->action != 0 && 
			    options->action != OPTION_CONFIG &&
			    options->action != OPTION_KEY) {
				printf(_("Only one action can be specified on the command line.\n"));
				goto error;
			}

			if (options->action == 0)
				options->action = OPTION_CONFIG;

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
			if (security_is_privileged() == 0) {
				printf(_("Only root can use the '--user' option\n"));
				exit(EXIT_FAILURE);
			}

			if (options->username) {
				printf(_("Multiple '--user' options passed\n"));
				exit(EXIT_FAILURE);
			}

			options->username = security_parse_user(optarg);
			if (!options->username) {
				printf(_("Illegal user specified on command prompt\n"));
				exit(EXIT_FAILURE);
			}
			break;

		case OPTION_VERBOSE:
			if (!security_is_privileged() && cfg->verbose_output == CONFIG_DISALLOW) {
				printf(_("Verbose output denied by policy.\n"));
				goto error;
			}

			cfg->pam_logging = 3;
			break;

		default:
			printf(_("Program error. You shouldn't end up here.\n"));
			assert(0);
			goto error;
		}
	}

	/* Check additional correctness */
	if (((options->flag_set_mask | options->flag_clear_mask) & FLAG_SALTED)
	    && (options->action != 'k')) {
		printf(_("The \"salt\" flag can only be specified during key creation!\n"));
		goto error;
	}

	if (!options->username) {
		/* User not specified, use the one who has ran us */
		options->username = security_get_calling_user();
		if (!options->username) {
			printf(_("Unable to determine name of current user!\n"));
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

	/* Reconfigure printing subsystem; -v might be passed */
	switch (cfg->pam_logging) {
	case 0: print_config(PRINT_STDOUT | PRINT_NONE); break;
	case 1: print_config(PRINT_STDOUT | PRINT_ERROR); break;
	case 2: print_config(PRINT_STDOUT | PRINT_WARN); break; 
	case 3: print_config(PRINT_STDOUT | PRINT_NOTICE); break; 
	default:
		assert(0);
		retval = 1;
		goto cleanup;
	}

	/* Perform action */
	switch (options->action) {
	case 0:
		printf(_("No action specified. Try passing -k, -s, -t or -l\n\n"));
		_usage(argc, (const char **) argv);
		retval = 1;
		goto cleanup;

	case OPTION_HELP:
		_usage(argc, (const char **)argv);
		retval = 0;
		break;

	case OPTION_KEY:
	case OPTION_REMOVE:
		retval = action_key(options);
		break;

	case OPTION_SPASS:
		retval = action_spass(options);
		break;

	case OPTION_ALPHABETS:
	case OPTION_CONFIG:
	case OPTION_INFO:
	case OPTION_INFO_KEY:
		retval = action_flags(options);
		break;

	case OPTION_AUTH:
		ret = action_authenticate(options);
		if (ret == 0)
			retval = 1;
		else
			retval = 0;
		break;
	case OPTION_VERSION:
		retval = action_license(options);
		break;

	case OPTION_WARN:
	case OPTION_SKIP:
	case OPTION_TEXT:
	case OPTION_LATEX:
	case OPTION_PROMPT:
		retval = action_print(options);
		break;

	case OPTION_CHECK:
		printf(_("*** Running testcases\n"));
		{
			int tmp;
			int failed = 0;

			/* Change DB info so we won't overwrite anything
			 * important */
			strcpy(cfg->user_db_path, ".otpasswd_testcase");
			strcpy(cfg->global_db_path, "/tmp/otshadow_testcase");
			cfg->db = CONFIG_DB_USER;

			tmp = num_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d num testcases failed\n******\n", tmp);

			tmp = config_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d config testcases failed\n******\n", tmp);

			tmp = state_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d state testcases failed\n******\n", tmp);

			tmp = crypto_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d crypto testcases failed\n******\n", tmp);

			tmp = card_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d card testcases failed\n******\n", tmp);

			tmp = ppp_testcase();
			failed += tmp;
			if (tmp)
				printf("******\n*** %d ppp testcases failed\n******\n", tmp);


			if (failed) {
				printf(_("***********************************************\n"
				         "*         !!! %d testcases failed !!!         *\n"
				         "* Don't use this release until this is fixed! *\n"
				         "* Note: Testcases should be run with default  *\n"
				         "* conpilation options and config.             *\n"
				         "* If unsure, reinstall and rerun --check      *\n"
				         "***********************************************\n"),
					failed);
				retval = 1;
			} else {
				printf(_("**********************************\n"
				         "* All testcases seem successful. *\n"
				         "**********************************\n"));
				retval = 0;
			}
			break;
		}

	default:
		printf(_("Program error. You shouldn't end up here.\n"));
		assert(0);
		retval = 1;
		goto cleanup;
	}


cleanup:
	free(options->action_arg);
	free(options->label);
	free(options->contact);
	free(options->username);
	ppp_fini();
	return retval;
}


#if 0
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

	/* 0) Initialize locale */
	locale_init();

	/* 1) Init safe environment, store current uids, etc. */
	security_init();

	/* After this point we can use stdout. 
	 * We might be:
	 * a) Run by root.
	 * b) Set-uid root. (On DB=global or user)
	 * c) Not set-uid. (DB=user)
	 *
	 * Now, try to read config file, init printing etc.
	 */

	ret = ppp_init(PRINT_STDOUT);
	if (ret != 0) {
		puts(_(ppp_get_error_desc(ret)));
		puts("");
		printf(_("OTPasswd not correctly installed.\n"));
		printf(_("Consult installation manual for detailed information.\n"));
		ppp_fini();
		return 1;
	}

	cfg = cfg_get();

	/* If DB is global, mysql or ldap, utility must be SUID root. 
	 * We can't detect this easily if we are run by root. So, 
	 * treat root as run by suid.
	 */
	if (security_is_suid() == 0 && 
	    cfg->db != CONFIG_DB_USER &&
	    security_is_privileged() == 0) {
		/* Something is wrong. We are not SUID.
		 * Or we're run as SUID user which is also bad.
		 */
		printf(
			_("Database type set to global, MySQL or LDAP, yet program "
			  "is not a SUID root.\n"));
		ppp_fini();
		return 1;
	}

	/* 4) We must drop permissions now. 
	 * If DB=user - drop to the user who called us.
	 * If DB=global - drop to cfg->user_uid
	 */
	switch (cfg->db) {
	case CONFIG_DB_GLOBAL:
		/* Drop root permanently to the cfg->user_uid 
		 * We do this even if we are run as root. */
		security_permanent_switch(cfg->user_uid, cfg->user_gid);
		break;
		
	case CONFIG_DB_MYSQL:
	case CONFIG_DB_LDAP:
	case CONFIG_DB_USER:
		/* Drop permanently back to the user who called us */
		/* FIXME: User won't be able to ptrace us 
		   rather and get passwords... */
		if (!security_is_privileged()) {
			/* We don't drop if we are root, so the --user
			 * option will work. */
			security_permanent_drop();
		}
		break;
	}

	/* 5) Config read. Privileges dropped. Parse user data. */
	ret = process_cmd_line(argc, argv, &options, cfg);
	if (ret != 0)
		return ret;

	ret = perform_action(argc, argv, &options, cfg);
	return ret;
}

#endif




extern char **environ;
int main(int argc, char **argv)
{
	int ret;
	agent *a = NULL;

	a = agent_connect(NULL);
	if (a == NULL) {
		printf("Unable to connect to agent.\n");
		puts(agent_strerror());
		return 1;
	}

	// superuser only: agent_set_user(a, "user");
	ret = agent_key_generate(a);

	

	ret = agent_disconnect(a);
	if (ret != 0) { 
		printf("Error while disconnecting from agent\n");
	}

	return 0;
}
