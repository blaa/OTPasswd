#ifndef _PASSCARDS_H_
#define _PASSCARDS_H_

#include "state.h"

/* Returns allocated memory with one passcard
 * "Number" is a passcard number. These functions 
 * add salt when needed. */
extern char *card_ascii(const state *s, const mpz_t number);

/* Returns allocated memory with LaTeX document with 6 passcards */
extern char *card_latex(const state *s, const mpz_t number);

extern void card_testcase(void);
#endif
