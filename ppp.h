#ifndef _PPP_H_
#define _PPP_H_

#include <gmp.h>
#include "state.h"

#define ROWS_PER_CARD 10

extern int ppp_get_passcode(state *s, const mpz_t counter, char *passcode);
extern void ppp_testcase(void);
#endif
