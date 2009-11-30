#ifndef _PPP_H_
#define _PPP_H_

#include <gmp.h>
#include "state.h"

/* Decode card number and XY code position into a counter */
extern int ppp_get_passcode_number(
	const state *s, const mpz_t passcard,
	mpz_t passcode, char column, char row);

/* Calculate a single passcode of given number using specified key */
extern int ppp_get_passcode(const state *s, const mpz_t counter, char *passcode);

/* Calculate card parameters and save them in state */
extern void ppp_calculate(state *s);

/* Generate prompt used for authentication; free returned value */
extern const char *ppp_get_prompt(state *s);

/* Clear and free prompt */
extern void ppp_dispose_prompt(state *s);

/* Try to authenticate user; returns 0 on successful authentication */
extern int ppp_authenticate(const state *s, const char *passcode);

extern void ppp_testcase(void);

#endif
