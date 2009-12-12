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
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <gmp.h>

#include <assert.h>

#include "print.h"
#include "crypto.h"
#include "num.h"

#include "passcards.h"

#define PPP_INTERNAL
#include "ppp.h"

#include "otpasswd_actions.h"
#include "testcases.h"

static const char *_program_name(const char *argv0)
{
	const char *pos = strrchr(argv0, '/');
	if (pos)
		return pos+1;
	else
		return argv0;
}

static void _usage(int argc, const char **argv)
{
	const char *prog_name =	_program_name(argv[0]);
	fprintf(stderr,
		"Usage: %s [options]\n"
		"Actions:\n"
		"  -k, --key    Generate a new key. Also resets all flags\n"
		"               and prints first passcard immediately\n"
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
		"  number      - specify a passcode with a decimal number\n"
		"  [number]    - a passcard number\n"
		"  CRR[number] - specify a passcode in passcard of a given number.\n"
		"                C is its column (A through G), RR - row (1..10)\n"
		"  current     - passcode used for next time authentication\n"
		"  next        - first, not yet printed, passcard\n"

		"\nConfiguration:\n"
		"  -f, --flag <arg>\n"
		"               Manages various user-selectable flags:\n"
		"               skip              skip passcode on failure (default)\n"
		"               dont-skip         do not skip passcodes on failure\n"
		"               show              show passcode while authenticating (default)\n"
		"               dont-show         do not show passcode\n"
		"               alphabet-simple   64-character alphabet (default)\n"
		"               alphabet-extended 88-character alphabet\n"
		"               codelenght-X      sets passcodes length, X is a number\n"
		"                                 from 2 to 16 (default: codelength-4)\n"
		"               list              print current state data\n"
		"  -p, --password <pass>\n"
		"               Set static password.\n"
		"  -c, --contact <arg>\n"
		"               Set a contact info (e.g. phone number) with which\n"
		"               you want to receive current passcode during authentication.\n"
		"               Details depends on pam module configuration. Use \"\"\n"
		"               to disable.\n"
		"  -d, --label <arg>\n"
		"               Set a caption to use on generated passcards.\n"
		"               Use \"\" to set default (hostname)\n"
		"  -n, --no-salt\n"
		"               Meaningful only during key generation. Disables salting\n"
		"               of a passcode counter. Enabling this option will make program\n"
		"               compatible with PPPv3 and will increase available passcard number\n"
		"               at the cost of (theoretically) less security.\n"
		"\n"
		"  -v, --verbose Display more information about what is happening.\n"
		"  --license     Display license, warranty, version and author information.\n"
		"  --check       Run all testcases.\n"

		"\nNotes:\n"
		"  \"dont-skip\" flag might introduce a security hole.\n"
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

int process_cmd_line(int argc, char **argv)
{
	int retval = 0;
	options_t options = {
		.log_level = PRINT_WARN,
		.action = 0,
		.action_arg = NULL,

		.flag_set_mask = 0,
		.flag_clear_mask = 0,
		.set_codelength = 0
	};

	static struct option long_options[] = {
		/* Action selection */
		{"key",			no_argument,		0, 'k'}, /* L used up */
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
		{"verbose",		required_argument,	0, 'v'},
		{"check",		no_argument,		0, 'x'},
		{"license",		no_argument,		0, 'Q'},

		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "ks:t:l:P:a:wf:p:d:c:nv", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
			/* Argument-less actions */
		case 'Q':
		case 'w':
		case 'k':
		case 'x':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(EXIT_FAILURE);
			}
			options.action = c;
			break;

			/* Actions with argument */
		case 's':
		case 't':
		case 'l':
		case 'P':
		case 'a':
		case 'p':
		case 'd':
		case 'c':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(EXIT_FAILURE);
			}
			options.action = c;

			if (optarg) 
				options.action_arg = strdup(optarg);
			else
				options.action_arg = NULL;
			break;

		case 'n':
			if (options.flag_set_mask != 0) {
				printf("-n option can only be passed during key creation!\n");
				exit(EXIT_FAILURE);
			}

			options.flag_set_mask |= FLAG_NOT_SALTED;
			break;

		case 'f':
			if (options.action != 0 && options.action != 'f') {
				printf("Only one action can be specified on the command line\n");
				exit(EXIT_FAILURE);
			}

			if (options.flag_set_mask & FLAG_NOT_SALTED) {
				printf("-n option can only be passed during key creation!\n");
				exit(EXIT_FAILURE);
			}

			assert(optarg != NULL);

			if (strcmp(optarg, "skip") == 0)
				options.flag_set_mask |= FLAG_SKIP;
			else if (strcmp(optarg, "dont-skip") == 0)
				options.flag_clear_mask |= FLAG_SKIP;
			else if (strcmp(optarg, "show") == 0)
				options.flag_set_mask |= FLAG_SHOW;
			else if (strcmp(optarg, "dont-show") == 0)
				options.flag_clear_mask |= FLAG_SHOW;
			else if (strcmp(optarg, "alphabet-simple") == 0)
				options.flag_clear_mask |= FLAG_ALPHABET_EXTENDED;
			else if (strcmp(optarg, "alphabet-extended") == 0)
				options.flag_set_mask |= FLAG_ALPHABET_EXTENDED;
			else if (strcmp(optarg, "list") == 0) {
				if (options.action != 0) {
					printf("Only one action can be specified on the command line\n"
						"and you can't mix 'list' flag with other flags.\n");
					exit(EXIT_FAILURE);
				}

				options.action = 'L'; /* List! Instead of changing flags */
			} else {
				int tmp;
				if (sscanf(optarg, "codelength-%d", &tmp) == 1) {
					options.set_codelength = tmp;
				} else {
					/* Illegal flag */
					printf("No such flag %s\n", optarg);
					exit(EXIT_FAILURE);
				}
			}

			if (options.action != 'L')
				options.action = 'f';
			break;

		case '?':
			/* getopt_long already printed an error message. */
			_usage(argc, (const char **)argv);
			exit(EXIT_FAILURE);
			break;

		case 'v':
			options.log_level = PRINT_NOTICE;
			break;

		default:
			printf("Got %d %c\n", c, c);
			assert(0);
		}
	}

	/* Perform action */
	if (print_init(options.log_level, 1, 0, NULL) != 0) {
		printf("Unable to start debugging\n");
	}
	int ret;
	switch (options.action) {
	case 0:
		print(PRINT_ERROR, "No action specified. Try passing -k, -s, -t or -l\n\n");
		_usage(argc, (const char **) argv);
		exit(1);

	case 'k':
		action_key(&options);
		break;

	case 'L': /* list action */
	case 'f':
	case 'd':
	case 'c':
	case 'p':
		action_flags(&options);
		break;

	case 'a':
		ret = action_authenticate(&options);
		print_fini();
		if (ret == 0)
			retval = 1;
		break;
	case 'Q':
		action_license(&options);
		break;

	case 'w': /* Warning */
	case 's':
	case 't':
	case 'l':
	case 'P':
		action_print(&options);
		break;

	case 'x':
		printf("*** Running testcases\n");
		{
			int failed = 0;
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

	if (options.action_arg)
		free(options.action_arg);
	print_fini();
	return retval;
}


int main(int argc, char **argv)
{
	return process_cmd_line(argc, argv);
}
