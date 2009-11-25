#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <gmp.h>

#include <assert.h>

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "ppp.h"
#include "state.h"

static const char *_program_name(const char *argv0)
{
	const char *pos = strrchr(argv0, '/');
	if (pos)
		return pos;
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
	
	if (strcasecmp(buf, "yes\n") == 0) 
		return 0;

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
		"  -s, --skip <num>\n"
		"               Skip to a card specified as an argument.\n"
		"  -t, --text <num>\n"
		"               Generate one ascii passcard of a specified number\n"
		"  -l, --latex <num>\n"
		"               Generate a latex file with 6 passcards\n"
		"               starting with the specified one\n"
		"\n"
		"  -p, --passcode <num | CRR[X] | current>\n"
		"               Specify a single passcode identifier to print.\n"
		"               Where:\n"
		"               num     - is an absolute passcode number, alternatively:\n"
		"               C       - column code (A through G)\n"
		"               RR      - row code (1 through 10)\n"
		"               X       - passcard number (CRRX example: B4[10])\n"
		"               current - current passcode, which will be\n"
		"                         used next time for the authentication.\n"
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
		"\n"
		"  -v, --verbose      Display more information about what is happening.\n"
		"\nNotes:\n"
		"  \"dont-skip\" flag might introduce a security hole.\n"
		"  Both --text and --latex can get \"next\" as a parameter which\n"
		"  will print the first not-yet printed passcard\n"
		"\nExamples:\n"
		"%s --key                generate new key\n"
		"%s --text 3             print third passcard to standard output\n"
		"%s --flag codelength-5  use 5-character long passcodes\n",
		prog_name, prog_name, prog_name, prog_name

		);
}

struct cmds {
	int log_level;
	char action;

	unsigned int flag_set_mask;
	unsigned int flag_clear_mask;
	int set_codelength;
} options = {
	.log_level = PRINT_ERROR,
	.action = 0,


	.flag_set_mask = 0,
	.flag_clear_mask = 0,
	.set_codelength = 0
};


/* Generate new key */
static void action_key(void)
{
	state s;
	if (state_init(&s) != 0) {
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

	if (state_key_generate(&s) != 0) {
		print(PRINT_ERROR, "Unable to generate new key\n");
		exit(1);
	}

	/* TODO: print first page in text */


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to ~/" STATE_FILENAME " file\n");
		exit(1);		
	}

	state_fini(&s);
}

/* Update flags based on mask which are stored in options struct */
static void action_flags(void)
{
	state s;
	if (state_init(&s) != 0) {
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
		s.passcode_length = options.set_codelength;
	else if (options.set_codelength) {
		print(PRINT_ERROR, "Illegal passcode length specified\n");
		goto cleanup;
	}


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to ~/" STATE_FILENAME " file\n");
		exit(1);		
	}


	printf("Flags updated, current configuration: ");

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

	printf("codelength-%d\n", s.passcode_length);

cleanup:
	state_fini(&s);	
}

void process_cmd_line(int argc, char **argv)
{

	static struct option long_options[] = {
		/* Action selection */
		{"key",			no_argument,		0, 'k'},
		{"skip",		required_argument,	0, 's'},
		{"text",		required_argument,	0, 't'},
		{"latex",		required_argument,	0, 'l'},
		{"passcode",		required_argument,	0, 'p'},
		
		/* Flags */
		{"flags",		required_argument,	0, 'f'},
		{"verbose",		required_argument,	&options.log_level, PRINT_NOTICE},
		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "ks:t:l:p:f:v", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'k':
		case 's':
		case 't':
		case 'l':
		case 'p':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
				exit(-1);
			}
			options.action = c;
			/* Parse argument */
			break;

		case 'f':
			if (options.action != 0) {
				printf("Only one action can be specified on the command line\n");
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
			else {
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
		case '?':
			/* getopt_long already printed an error message. */
			_usage(argc, (const char **)argv);
			exit(-1);
			break;

		default:
			abort();
		}
	}
	
	/* Perform action */
	print_init(options.log_level, 1, 0, NULL);

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
	}




}


int main(int argc, char **argv)
{
	process_cmd_line(argc, argv);
	return 0;
}
