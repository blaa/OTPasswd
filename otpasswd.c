/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * (C) 2009 by Tomasz bla Fortuna <bla@thera.be>, <bla@af.gliwice.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * See LICENSE file for details.
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
#include "ppp.h"
#include "state.h"
#include "passcards.h"

static int is_passcard_in_range(const state *s, const mpz_t passcard)
{
	/* 1..max_passcode/codes_on_passcard */
	if (mpz_cmp_ui(passcard, 1) < 0) {
		printf("Card numbering starts at 1\n");
		return 0; /* false */
	}

	if (mpz_cmp(passcard, s->max_card) > 0) {
		gmp_printf("Number of the last available passcard is %Zd\n", s->max_card);
		return 0;
	}

	return 1;
}

static int is_passcode_in_range(const state *s, const mpz_t passcard)
{
	/* 1..max_which_depends_on_salt and passcard configuration */
	if (mpz_cmp_ui(passcard, 1) < 0)
		return 0; /* false */

	if (mpz_cmp(passcard, s->max_code) > 0) {
		gmp_printf("Number of the last available passcode is %Zd\n", s->max_code);
		return 0;
	}

	return 1;
}

static const char *_program_name(const char *argv0)
{
	const char *pos = strrchr(argv0, '/');
	if (pos)
		return pos+1;
	else
		return argv0;
}

/* Ask a question; return 0 only if "yes" was written, 1 otherwise */
static int _yes_or_no(const char *msg)
{
	char buf[20];

	printf("%s (yes/no): ", msg);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		/* End of file? */
		printf("\n");
		return 1;
	}

	if (strcasecmp(buf, "yes\n") == 0) {
		printf("\n");
		return 0;
	}

	return 1;
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
		"  -p, --prompt <which>\n"
		"               Display authentication prompt for given passcode\n"
		"  -a, --authenticate <passcode>\n"
		"               Try to authenticate with given passcode\n"
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
		"               list              not a real flag; will just print current\n"
		"\n                               list of flags\n"
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
		"  --license     Display license, warranty and author information.\n"
		"  --check       Run all testcases.\n"

		"\nNotes:\n"
		"  \"dont-skip\" flag might introduce a security hole.\n"
		"  Both --text and --latex can get \"next\" as a parameter which\n"
		"  will print the first not-yet printed passcard\n"
		"\nExamples:\n"
		"%s --key                generate new key\n"
		"%s --text '[3]'         print third passcard to standard output\n"
		"%s --flag codelength-5  use 5-character long passcodes\n"
		"Generate a 6 passcards on A4 page using LaTeX:\n"
		"%s --latex next > tmp.latex\n"
		"pdflatex tmp.latex\n",
		prog_name, prog_name, prog_name, prog_name, prog_name
		);
}

struct cmds {
	int log_level;
	char action;
	char *action_arg;

	unsigned int flag_set_mask;
	unsigned int flag_clear_mask;
	int set_codelength;
} options = {
	.log_level = PRINT_WARN, /* Default log level */
	.action = 0,
	.action_arg = NULL,

	.flag_set_mask = 0,
	.flag_clear_mask = 0,
	.set_codelength = 0
};


/* Authenticate; returns boolean; 1 - authenticated */
static int action_authenticate(void)
{
	int retval = 0;

	/* OTP State */
	state s;

	if (state_init(&s, NULL, NULL) != 0) {
		/* This will fail if we're unable to locate home directory */
		print(PRINT_ERROR, "Unable to load state! Have you used -k option?\n");
		return 0; /* False - not authenticated */
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_load_increment(&s);
	switch (retval) {
	case 0:
		/* Everything fine */
		break;

	case STATE_NUMSPACE:
		printf("Counter overflowed. Regenerate key\n");
		retval = 0;
		goto cleanup;

	case STATE_DOESNT_EXISTS:
		retval = 0;
		goto cleanup;
		
	default: /* Any other problem - error */
		retval = 0;
		goto cleanup;
	}

	/* Generate prompt */
	ppp_calculate(&s);

	if (ppp_authenticate(&s, options.action_arg) == 0) {
		/* Correctly authenticated */
		retval = 1;
		goto cleanup;
	}

cleanup:
	if (retval)
		printf("Authentication successful.\n");
	else 
		printf("Authentication failed.\n");
		
	state_fini(&s);
	free(options.action_arg);
	return retval;
}

/* Generate new key */
static void action_key(void)
{
	state s;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	/* Check existance of previous key */
	if (state_load(&s) == 0) {
		/* We loaded state correctly, key exists */
		if (_yes_or_no("This will erase irreversibly your previous key.\n"
			       "Are you sure you want to continue?") != 0) {
			printf("Stopping\n");
			exit(1);
		}
	}

	int salted = options.flag_set_mask & FLAG_NOT_SALTED ? 0 : 1;
	s.flags |= options.flag_set_mask;

	if (state_key_generate(&s, salted) != 0) {
		print(PRINT_ERROR, "Unable to generate new key\n");
		exit(1);
	}

	/* TODO: print first page in text */


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to %s file\n", s.filename);
		exit(1);
	}

	state_fini(&s);
}

static void action_license(void)
{
	printf(
		"otpasswd -- One-time password manager and PAM module.\n"
		"Copyright (C) 2009 Tomasz bla Fortuna\n"
		"\n"
		"This program is free software: you can redistribute it and/or modify\n"
		"it under the terms of the GNU General Public License as published by\n"
		"the Free Software Foundation, either version 3 of the License, or\n"
		"(at your option) any later version.\n"
		"\n"
		"This program is distributed in the hope that it will be useful,\n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
		"GNU General Public License for more details.\n"
		"\n"
		"You should have received a copy of the GNU General Public License\n"
		"along with this program in a LICENSE file.\n"
	);
}

/* Update flags based on mask which are stored in options struct */
static void action_flags(void)
{
	state s;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	/* Load our state */
	if (state_load(&s) != 0) {
		/* Unable to load state */
		print(PRINT_ERROR, "Error while reading state, have you created a key with -k option?\n");
		exit(1);
	}

	/* Change flags */
	s.flags |= options.flag_set_mask;
	s.flags &= ~(options.flag_clear_mask);

	if (options.set_codelength >= 2 && options.set_codelength <= 16)
		s.code_length = options.set_codelength;
	else if (options.set_codelength) {
		print(PRINT_ERROR, "Illegal passcode length specified\n");
		goto cleanup;
	}


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to ~/" STATE_FILENAME " file\n");
		exit(1);
	}

	if (options.flag_set_mask || options.flag_clear_mask)
		printf("Flags updated, current configuration: ");
	else
		printf("Flags not changed, current configuration: ");
	if (s.flags & FLAG_SHOW)
		printf("show ");
	else
		printf("dont-show ");

	if (s.flags & FLAG_SKIP)
		printf("skip ");
	else
		printf("dont-skip ");

	if (s.flags & FLAG_ALPHABET_EXTENDED)
		printf("alphabet-extended ");
	else
		printf("alphabet-simple ");

	if (s.flags & FLAG_NOT_SALTED)
		printf("(no salt) ");
	else
		printf("(key salted) ");

	printf("codelength-%d\n", s.code_length);

cleanup:
	state_fini(&s);
}

void action_print(void)
{
	int ret;

	/* This action requires a created key */
	state s;
	int state_locked = 1;
	int state_changed = 0;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	ret = state_lock(&s);
	if (ret != 0 && ret != STATE_DOESNT_EXISTS) {
		/* whoops! */
		print(PRINT_ERROR, "Unable to lock file! Unable to save"
		      " any changes back to file!\n");
		state_locked = 0;
	}

	/* Load our state */
	if (state_load(&s) != 0) {
		print(PRINT_ERROR, "Unable to load state file. Have you tried -k option?\n");
		goto cleanup;
	}

	/* Calculate current cards etc */
	ppp_calculate(&s);

	/* See if we have any counters left */
	int counter_correct = 1;
	ret = ppp_verify_range(&s);
	if (ret == 2) {
		/* State file corrupted */
		goto cleanup;
	}

	if (ret != 0)
		counter_correct = 0;

	/* Parse argument, we need card number + passcode number */
	int code_selected = 0;
	mpz_t passcard_num;
	mpz_t passcode_num;
	mpz_init(passcard_num);
	mpz_init(passcode_num);

	if (strcasecmp(options.action_arg, "current") == 0) {
		/* Current passcode */
		if (counter_correct == 0) {
			print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 1;
		mpz_set(passcode_num, s.counter);

	} else if (strcasecmp(options.action_arg, "next") == 0) {
		/* Next passcard */
		if (counter_correct == 0) {
			print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 0;
		mpz_set(passcard_num, s.furthest_printed);
	} else if (isalpha(options.action_arg[0])) {
		/* Format: CRR[number] */
		char column;
		int row;
		char number[41];
		ret = sscanf(options.action_arg, "%c%d[%40s]", &column, &row, number);
		column = toupper(column);
		if (ret != 3 || (column < 'A' || column > 'J')) {
			print(PRINT_ERROR, "Incorrect passcode specification. (%d)\n", ret);
			goto cleanup1;
		}

		ret = gmp_sscanf(number, "%Zu", passcard_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Incorrect passcard specification.\n");
			goto cleanup1;
		}

		if (!is_passcard_in_range(&s, passcard_num)) {
			print(PRINT_ERROR,
			      "Passcard number out of range. "
			      "First passcard has number 1.\n");
			goto cleanup1;
		}

		/* ppp_get_passcode_number adds salt as needed */
		ret = ppp_get_passcode_number(&s, passcard_num, passcode_num, column, row);
		if (ret != 0) {
			print(PRINT_ERROR, "Error while parsing passcard description.\n");
			goto cleanup1;
		}

		code_selected = 1;

	} else if (isdigit(options.action_arg[0])) {
		/* All characters must be a digit! */
		int i;
		for (i=0; options.action_arg[i]; i++) {
			if (!isdigit(options.action_arg[i])) {
				print(PRINT_ERROR, 
				      "Illegal passcode number!\n");
				goto cleanup1;
			}
		}


		/* number -- passcode number */
		ret = gmp_sscanf(options.action_arg, "%Zd", passcode_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Error while parsing passcode number.\n");
			goto cleanup1;
		}

		if (!is_passcode_in_range(&s, passcode_num)) {
			print(PRINT_ERROR, "Passcode number out of range.\n");
			goto cleanup1;
		}

		mpz_sub_ui(passcode_num, passcode_num, 1);

		/* Add salt and this number cames from user */
		ppp_add_salt(&s, passcode_num);

		code_selected = 1;
	} else if (options.action_arg[0] == '['
		   && options.action_arg[strlen(options.action_arg)-1] == ']') {
		/* [number] -- passcard number */
		ret = gmp_sscanf(options.action_arg, "[%Zd]", passcard_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Error while parsing passcard number.\n");
			goto cleanup1;
		}

		if (!is_passcard_in_range(&s, passcard_num)) {
			print(PRINT_ERROR, "Passcard out of accessible range.\n");
			goto cleanup1;
		}

		mpz_sub_ui(passcard_num, passcard_num, 1);
		code_selected = 0;
	} else {
		print(PRINT_ERROR, "Illegal argument passed to option.\n");
		goto cleanup1;
	}


	/* Print the thing requested */
	if (code_selected == 0) {
		char *card;
		switch (options.action) {
		case 't':
			card = card_ascii(&s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup1;
			}
			puts(card);
			free(card);
			break;

		case 'l':
			card = card_latex(&s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup1;
			}
			puts(card);
			free(card);
			break;

		case 's':
			if (counter_correct == 0) {
				print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}

			break;
			
		case 'p':
			print(PRINT_ERROR, "Option requires passcode as argument\n");
			break;
		}
	} else {
		char passcode[17];
		const char *prompt;
		switch (options.action) {
		case 't':
			/* ppp_get_passcode wants internal
			 * passcodes (with salt) */
			ret = ppp_get_passcode(&s, passcode_num, passcode);
			if (ret != 0) {
				print(PRINT_ERROR, "Error while calculating passcode\n");
				goto cleanup1;
			}
			printf("%s\n", passcode);
			break;

		case 'l':
			print(PRINT_ERROR,
			      "LaTeX parameter works only with"
			      " passcard specification\n");
			break;

		case 's':
			if (counter_correct == 0) {
				print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}

			break;
			
		case 'p':

			/* Don't save state after this operation */
			mpz_set(s.counter, passcode_num);
			ppp_calculate(&s);
			prompt = ppp_get_prompt(&s);
			printf("%s\n", prompt);

			break;
		}
	}

cleanup1:
	num_dispose(passcode_num);
	num_dispose(passcard_num);

cleanup:
	if (state_changed) {
		if (state_locked == 0)  {
			print(PRINT_NOTICE,  "NOT saving any changes since file is locked\n");
		} else {
			print(PRINT_NOTICE, "Saving changes to state file\n");
			if (state_store(&s) != 0) {
				print(PRINT_ERROR, "Error while saving changes!\n");
			}
		}
	}
	state_fini(&s);
	state_unlock(&s);
}


void process_cmd_line(int argc, char **argv)
{

	static struct option long_options[] = {
		/* Action selection */
		{"key",			no_argument,		0, 'k'},
		{"skip",		required_argument,	0, 's'},
		{"text",		required_argument,	0, 't'},
		{"latex",		required_argument,	0, 'l'},
		{"prompt",		required_argument,	0, 'p'},
		{"authenticate",	required_argument,	0, 'Q'},

		/* Flags */
		{"flags",		required_argument,	0, 'f'},
		{"label",		required_argument,	0, 'd'},
		{"contact",		required_argument,	0, 'c'},
		{"no-salt",		no_argument,		0, 'n'},
		{"verbose",		required_argument,	0, 'v'},
		{"check",		no_argument,		0, 'x'},
		{"license",		no_argument,		0, 'a'},

		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "ks:t:l:p:a:f:d:c:nv", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'k':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}
			options.action = c;
			break;

		case 's':
		case 't':
		case 'l':
		case 'p':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}
			options.action = c;
			options.action_arg = strdup(optarg);
			/* Parse argument */
			break;

		case 'a':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}
			options.action = c;
			options.action_arg = strdup(optarg);
			break;

		case 'n':
			if (options.flag_set_mask) {
				printf("-n option can only be passed during key creation!\n");
				exit(-1);
			}

			options.flag_set_mask |= FLAG_NOT_SALTED;
			break;

		case 'f':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}

			if (options.flag_set_mask) {
				printf("-n option can only be passed during key creation!\n");
				exit(-1);
			}

			options.action = 'f';
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
				/* Nothing */
			} else {
				int tmp;
				if (sscanf(optarg, "codelength-%d", &tmp) == 1) {
					options.set_codelength = tmp;
				} else {
					/* Illegal flag */
					printf("No such flag %s\n", optarg);
					exit(1);
				}
			}
			break;

		case 'd':
		case 'c':
			printf("Unimplemented\n");
			assert(0);

		case '?':
			/* getopt_long already printed an error message. */
			_usage(argc, (const char **)argv);
			exit(-1);
			break;

		case 'x':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}
			options.action = 'x';
			break;

		case 'v':
			options.log_level = PRINT_NOTICE;
			break;

		case 'Q':
			options.action = 'Q';
			break;

		default:
			printf("Got %d %c\n", c, c);
			assert(0);
		}
	}

	/* Perform action */
	print_init(options.log_level, 1, 0, NULL);
	int ret;
	switch (options.action) {
	case 0:
		print(PRINT_ERROR, "No action specified. Try passing -k, -s, -t or -l\n\n");
		_usage(argc, (const char **) argv);
		exit(1);

	case 'k':
		action_key();
		break;

	case 'f':
		action_flags();
		break;

	case 'a':
		ret = action_authenticate();
		print_fini();
		if (ret)
			exit(0);
		else
			exit(1);

	case 'Q':
		action_license();
		break;

	case 's':
	case 't':
	case 'l':
	case 'p':
	case 'P':
		action_print();
		free(options.action_arg);
		break;

	case 'x':
		printf("*** Running testcases\n");
		state_testcase();
		num_testcase();
		crypto_testcase();
		card_testcase();
		ppp_testcase();
	}

	print_fini();
}


int main(int argc, char **argv)
{
	process_cmd_line(argc, argv);
	return 0;
}
