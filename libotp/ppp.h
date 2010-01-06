/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009, 2010 by Tomasz bla Fortuna <bla@thera.be>
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
 * This function decreases passcard by one so counting starts at '1'.
 * Counter is created with salt included.
 */
extern int ppp_get_passcode_number(
	const state *s, const mpz_t passcard,
	mpz_t passcode, char column, char row);

/* Adds a salt to given passcode if salt is used
 * In other words: converts from user supplied passcode
 * into system passcode number. */
extern void ppp_add_salt(const state *s, mpz_t passcode);

/* Calculate a single passcode using Perfect Paper Passwords
 * algorithm. Key is taken from state, and counter passes as argument
 * (which is not further mangled. That is - it has to have a salt included). */
extern int ppp_get_passcode(const state *s, const mpz_t counter, char *passcode);

/* Return current passcode. Helper for ppp_get_passcode function. */
extern int ppp_get_current(const state *s, char *passcode);

/* Calculate card parameters and save them in state.  Required by many 
 * (ppp_get_prompt, ppp_verify_range) functions to work.
 * Should be called to update information after any flag, 
 * counter, etc. change */
extern void ppp_calculate(state *s);

/* Print to stdout all acceptable alphabets with IDs */
extern void ppp_alphabet_print(void);

/* Returns an ORed mask of warning conditions */
extern int ppp_get_warning_conditions(const state *s);

/* Return warning message for a warning condition
 * and clear this condition from flag. Returns NULL
 * when no conditions are left in argument.
 */
extern const char *ppp_get_warning_message(const state *s, int *warning);

/* Decode ppp_error (see ppp_common.h for list) */
extern const char *ppp_get_error_desc(int error);

/* Try to authenticate user; returns 0 on successful authentication */
extern int ppp_authenticate(const state *s, const char *passcode);

/**************************************
 * State/Policy verification 
 *************************************/

/* Verify that counter (and key) is in correct range 
 * done usually after reading from the state file, when 
 * the data could be maliciously changed */
extern int ppp_verify_range(const state *s);

/* Verify if an alphabet given as ID is correct 
 * and allowed by policy. */
extern int ppp_verify_alphabet(int id);

/* Verify code length */
extern int ppp_verify_code_length(int length);

/* Verify user flags */
extern int ppp_verify_flags(int flags);

/* Verify all parts of user state */
extern int ppp_verify_state(const state *s);

/*******************************************
 * State Getters / Setters
 ******************************************/
enum {
	PPP_FIELD_FAILURES = 1,		/* unsigned int */
	PPP_FIELD_RECENT_FAILURES,	/* unsigned int */
	PPP_FIELD_CODE_LENGTH,		/* unsigned int */
	PPP_FIELD_ALPHABET,		/* unsigned int */
	PPP_FIELD_FLAGS,		/* unsigned int */

	PPP_FIELD_KEY,			/* mpz */
	PPP_FIELD_COUNTER, 		/* mpz */
	PPP_FIELD_LATEST_CARD,		/* mpz */

	PPP_FIELD_USERNAME,		/* char * */
	PPP_FIELD_PROMPT,		/* char * */
	PPP_FIELD_CONTACT,		/* char * */
	PPP_FIELD_LABEL,		/* char * */
};

/* Setters return '2' if argument is invalid 
 * (because of policy for example), both 
 * setters and getters return '1' if field is invalid 
 * and take the liberty to call assert(0) then. */

/* Get a value out of state and place at "arg" memory location.
 * In some cases this can also be int, not unsigned int.
 */
extern unsigned int ppp_get_int(const state *s, int field);

/* Get long number from state. */
extern int ppp_get_mpz(const state *s, int field, mpz_t arg);

/* Get character string from state. This sets "arg" memory 
 * to a pointer to state data. This data musn't be altered.
 * Returns 0 on success and 1 if field is incorrect. */
extern int ppp_get_str(const state *s, int field, const char **arg);

/* Int argument setter. options might equal PPP_CHECK_POLICY. */
extern int ppp_set_int(state *s, int field, unsigned int arg, int options);

/* Copy nul-terminated data passed as arg into state.
 * This function checks length of destination buffer
 * and policies (ignores policy if check_policy = 0). 
 * May return 1 if field is wrong (but will rather die).
 * Will return 2 if denied by policy
 * Will return 3 if too big 
 * "options" might equal PPP_CHECK_POLICY.
 */
extern int ppp_set_str(state *s, int field, const char *arg, int options);

/* Setter/getter/checker for flag fields. No policy checking now */
/* Check if flag is set in state, add flag and remove flag. */
extern int ppp_flag_check(const state *s, int flag);
extern void ppp_flag_add(state *s, int flag);
extern void ppp_flag_del(state *s, int flag);

/*******************************************
 * High level functions for state management
 *******************************************/

/* Allocate state information and initialize it. */
extern int ppp_init(state **s, const char *user);

/* Deinitialize state and free it's memory */
extern void ppp_fini(state *s);

/*
 * Lock state and load state.
 * Calculate PPP data (passcard sizes etc.)
 * Lock is left set.
 */
extern int ppp_load(state *s);

/*
 * Will ensure that the state was locked before
 * If store = 1 will update db with state information
 * If unlock = 1 will unlock state after writting.
 */
extern int ppp_release(state *s, int store, int unlock);

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

/* Lock & Read
 * If zero = 0 then increment failure and recent_failures count.
 * If zero = 1 then clear recent_failures.
 * Store & unlock
 */
extern int ppp_failures(const state *s, int zero);

#endif
