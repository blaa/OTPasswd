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

	printf("STATE TESTCASE\n");
	state_testcase();
	printf("STATE TESTCASE END\n");

	char passcode[6] = {0};
	ppp_get_passcode(&s, s.counter, passcode);
	printf("passcode: %s\n", passcode);

	num_testcase();
	crypto_testcase();
	return 0;
}
