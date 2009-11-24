#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include <assert.h>

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "ppp.h"
#include "state.h"

static const char *program_name(const char *argv0)
{
	const char *pos = strrchr(argv0, '/');
	if (pos)
		return pos;
	else
		return argv0;
}

static void usage(int argc, const char **argv)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"Options:\n"
		"  -k, --key          Generate a new sequence key and save in ~/" STATE_FILENAME "\n"
		"  -a, --alphabet <string>\n"
		"                     Optionally used with --key to specify a character set\n"
		"                     used for passcodes.\n"
		"  -s, --skip         Skip to --passcode or to --card specified.\n"
		"  -t, --text         Generate text passcards for printing.\n"
		"  -l, --latex        Generates latex file consisting of 6 passcards\n"
		"                     starting at the one specified with -c\n"
		"  -c, --card <num>   Specify number of passcard to --skip to or print.\n"
		"  -p, --passcode <RRC[NNNN]>\n"
		"                     Specify a single passcode identifier to --skip to or print.\n"
		"                     Where: NNNN is the decimal integer passcard number, C is\n"
		"                     the column (A through G), and RR is the row (1 through 10).\n"
		"                     Square brackets around NNNN and comma separators are optional.\n"
		"                     You can also specify \"current\" to get the next passcode\n"
		"                     which will be used for authentication.\n"
		"  --passphrase <phrase>\n"
		"                     Use the specified <phrase> to create a temporary key for\n"
		"                     testing purposes only.  This temporary key is not saved\n"
		"                     and will only be used until the program exits.\n"
		"  --dontSkip         Used with --key to specify that on authentication, system\n"
		"                     will not advance to the next passcode on a failed attempt.\n"
		"                     **DANGER** To avoid DoS attacks use requisite instead\n"
		"  --showPasscode     Used with --key to specify that on authentication, system\n"
		"                     will display passcode as it is typed.\n"
		"  -v, --verbose      Display more information about what is happening.\n",
		/* -u, --useVersion <N>              UNDOCUMENT feature used only for testing */
		program_name(argv[0])
		);
}



int main(int argc, char **argv)
{
	usage(argc, argv);
	return 0;
}
