/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * (C) 2009 by Tomasz bla Fortuna <bla@thera.be>, <bla@af.gliwice.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * See LICENSE file for details.
 **********************************************************************/

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
