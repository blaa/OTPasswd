#ifndef _PASSCARDS_H_
#define _PASSCARDS_H_

#include "state.h"

extern char *card_ascii(const state *s, mpz_t number);
extern char *card_latex(const state *s, mpz_t number);
extern void card_testcase(void);


#endif
