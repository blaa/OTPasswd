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

static void _usage(int argc, const char **argv)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"Options:\n"
		"  -k, --key          Generate a new sequence key and save in ~/" STATE_FILENAME "\n"
		"  -s, --skip         Skip to --passcode or to --card specified.\n"
		"  -t, --text         Generate text passcards for printing.\n"
		"  -l, --latex        Generates latex file consisting of 6 passcards\n"
		"                     starting at the one specified with -c\n"
		"  -c, --card <num>   Specify number of passcard to --skip to or print.\n"
		"  -p, --passcode <num | CRR | current>\n"
		"                     Specify a single passcode identifier to --skip to or print.\n"
		"                     Where:\n"
		"                     num     - is absolute passcode number, alternatively:\n"
		"                     C       - column code (A through G)\n"
		"                     RR      - row code (1 through 10)\n"
		"                     current - current passcode, which will be\n"
		"                               used for authentication.\n"
		"Flags:\n"
		"  --skip-on-fail <enabled|disabled> (default: enabled)\n"
		"                     Disabling skipping can help prevent DoS attacks,\n"
		"                     yet it might allow attacker to perform race-for-last key\n"
		"                     attack and should be avoided. \n"
		"  --show <enabled|disabled> (default: enabled)\n"
		"                     if enabled passcodes are shown during authentication\n"
		"  --alphabet <id> (default: 1)\n"
		"                     determine alphabet to be used for generating passcodes\n"
		"                     1 - 63 easy differentiable characters\n"
		"                     2 - more, less differentiable\n"
		"  --passcode-len <length> (default: 4)\n"
		"                     Set length of passcodes used\n"
		"  -v, --verbose      Display more information about what is happening.\n",
		_program_name(argv[0])
		);
}

struct {
	int verbose;
	int key;
	int skip;
	int text;
	int latex;
	int skip_on_fail;
	int show;
	int alphabet;
} command = {
	.verbose = 0,
	.key = 0,
	.skip = 0,
	.text = 0,
	.latex = 0,
	.skip_on_fail = 1,
	.show = 1,
	.alphabet = 1,
};

void processCommandLine(int argc, char **argv)
{
	static struct option long_options[] = {
		{"key",			no_argument,		&command.key, 1},
		{"skip",		no_argument,		0, 's'},
		{"text",		no_argument,		0, 't'},
		{"latex",		no_argument,		0, 'l'},

		{"card",		required_argument,	0, 'c'},

		{"next",		no_argument,		0, 1},

		{"passcode",		required_argument,	0, 'p'},

		{"skip-on-fail",	required_argument,	0, 1},
		{"show",		required_argument,	&command.show, 1},
		{"alphabet",		required_argument,	0, 'a'},
		{"verbose",		no_argument,		0, 'v'},
		{0, 0, 0, 0}
	};

	while (1) {
		int tmp;

		int option_index = 0;
		int c = getopt_long(argc, argv, "kstlc:p:va:", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			break;
		case 'c':
			break;
		case 'p':
			break;
		case 'v':

			if (sscanf(optarg, "%d", &tmp) != 1) {
				printf("verbose requires argument, a number 1-4\n");
				exit(-1);
			}
			command.verbose = tmp;
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

	if (argc > optind) {
		_usage(argc, (const char **)argv);
		exit(-1);
	}

}


int main(int argc, char **argv)
{
	_usage(argc, (const char **)argv);
	return 0;
}
