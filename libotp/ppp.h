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
#include "ppp_common.h"

#ifdef PPP_INTERNAL
#	include "state.h"
#else
typedef struct state state;

#endif

/* Decode external card number and XY code position into a counter 
 * This function decreases passcard by one.
 */
extern int ppp_get_passcode_number(
	const state *s, const mpz_t passcard,
	mpz_t passcode, char column, char row);

/* Adds a salt to given passcode if salt is used */
/* In other words: converts from user supplied passcode
 * into system passcode number */
extern void ppp_add_salt(const state *s, mpz_t passcode);

/* Calculate a single passcode of the given number using state key */
extern int ppp_get_passcode(const state *s, const mpz_t counter, char *passcode);

/* Calculate card parameters and save them in state.  Required by many 
 * (ppp_get_prompt, ppp_verify_range) functions to work. */
extern void ppp_calculate(state *s);

/* Verify that counter (and key) is in correct range 
 * done usually after reading from the state file, when 
 * the data could be maliciously changed */
extern int ppp_verify_range(const state *s);

/* Generate prompt used for authentication
 * Do not free returned value. It's stored in state
 * and freed in state_fini.
 */
extern const char *ppp_get_prompt(state *s);

/* Clear and free prompt */
extern void ppp_dispose_prompt(state *s);

/* Return current passcode */
extern int ppp_get_current(const state *s, char *passcode);

/* Get contact info */
const char *ppp_get_contact(const state *s);

enum ppp_warning{
	PPP_WARN_OK = 0,		/* No warning condition */
	PPP_WARN_LAST_CARD = 1,		/* User on last printed card */
	PPP_WARN_NOTHING_LEFT = 2	/* Used up all passcodes */
};
extern int ppp_get_warning_condition(const state *s);

/* Return warning message for a warning condition */
extern const char *ppp_get_warning_message(enum ppp_warning warning);


/* Try to authenticate user; returns 0 on successful authentication */
extern int ppp_authenticate(const state *s, const char *passcode);

/*******************************************
 * High level functions for state management
 *******************************************/

/* Currently just call low-level interface */
extern int ppp_init(state **s, const char *user);
extern void ppp_fini(state *s);

extern int ppp_is_flag(const state *s, int flag);

/*
 * Lock state
 * Load state 
 * Calculate PPP data (passcard sizes etc.)
 */
extern int ppp_load(state *s);

/*
 * Assert lock
 * Store file if requested
 * Unlock if requested
 */
extern int ppp_release(state *s, int store, int unlock);

extern const char *ppp_get_username(const state *s);

/*
 * 1. Lock file
 * 2a. Open it
 * 2b. Verify that we still can perform authentication
 *     (for example the counter is not bigger than 2^128)
 * 3. Increment counter
 * 4. Save it and unlock
 *
 * It also calls ppp_calculate();
 */
extern int ppp_increment(state *s);

/* THIS WAS USED FOR SKIPPING. NOT USED NOW.
 * Lock
 * Read
 * Decrement counter
 * Compare with current
 * Store decremented if nobody tried to authenticate in the meantime
 */
extern int ppp_decrement(state *s);

#endif
