#ifndef _PPP_H_
#define _PPP_H_

#include <gmp.h>

extern int ppp_get_passcode(
	const mpz_t key, const mpz_t counter, 
	char *passcode, const int length);

#endif
