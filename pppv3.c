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

int main(int argc, char **argv)
{
	state s;

	print_init(PRINT_NOTICE, 1, 0, NULL);

	state_init(&s);

	state_debug(&s);

	char passcode[6] = {0};
	ppp_get_passcode(s.sequence_key, s.counter, passcode, 4);
	printf("passcode: %s\n", passcode);

	num_testcase();
	crypto_testcase();
	return 0;
}
