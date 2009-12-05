/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with otpasswd. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/

#ifndef _PPP_H_
#define _PPP_H_

#include <gmp.h>
#include "state.h"

/* Decode external card number and XY code position into a counter 
 * This function decreases passcard by one.
 */
extern int ppp_get_passcode_number(
	const state *s, const mpz_t passcard,
	mpz_t passcode, char column, char row);

/* Adds a salt to given passcode if salt is used */
extern void ppp_add_salt(const state *s, mpz_t passcode);

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

/* Verify that counter (and key) is in correct range 
 * done usually after reading from the state file, when 
 * the data could be maliciously changed */
extern int ppp_verify_range(const state *s);

/* High level function used during authentication.
 * 1. Lock file
 * 2a. Open it
 * 2b. Verify that we still can perform authentication
 *     (for example the counter is not bigger than 2^128)
 * 3. Increment counter
 * 4. Save it and unlock
 *
 * It also calls ppp_calculate();
 */
extern int ppp_load_increment(state *s);

/* Locked read, compare and decrement
 *
 */
extern int ppp_load_decrement(state *s);

extern int ppp_testcase(void);

#endif
