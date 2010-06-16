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
 *
 * DESC:
 *   Main interface to the libotp. In future all operations on state
 *   will go through this module. Currently defining PPP_INTERNAL 
 *   allows user to get a view into state internals.
 **********************************************************************/

#ifndef _PPP_H_
#define _PPP_H_

/* Data shared between state and ppp */
#include "ppp_common.h"

/* Load state.h only if user explicitly requested it.
 * This file defines state struct internals which should
 * not be mangled by hand. Use ppp.h interface instead
 */
#ifdef PPP_INTERNAL
#	include "state.h"
#else
	typedef struct state state;
#endif

/* Load all standard libotp headers at once */
#include "print.h"
#include "config.h"
#include "crypto.h"
#include "num.h"


/*******************************************
 * Init/fini functions of libotp
 *******************************************/

/** First libotp function which should be called.
 * Call ppp_fini even if this functions fails.
 * Sets umask, starts printing subsystem and reads configuration. */
extern int ppp_init(int print_flags, const char *print_logfile);

/** Shuts down logging subsystem */
extern void ppp_fini(void);


/*******************************************
 * High level functions for state management
 *******************************************/
/** Allocate state information and initialize it. */
extern int ppp_state_init(state **s, const char *user);

/** Deinitialize state and free it's memory */
extern void ppp_state_fini(state *s);

/** Lock state and load state.
 * Calculate PPP data (passcard sizes etc.)
 * After this function finished correctly state
 * is still locked, so it can be modified. */
extern int ppp_state_load(state *s, int flags);

/** This function can store state back on the disc
 * and ensures it was locked before. 
 * If flags&PPP_STORE will update db with state information
 * If flags&PPP_UNLOCK will unlock state after writing. */
extern int ppp_state_release(state *s, int flags);

/** Generate key.
 * On contrary to any other actions, state shouldn't be locked
 * this time and ppp_state_release will allow storing freshly
 * generated state information without lock. 
 * 
 * That's because we must lock indifinetely on user action between
 * key generation and storing. User must see new passcard and decide
 * whether he is ready to use PPP.
 *
 *
 * \param flags can be set to PPP_POLICY_CHECK to check regeneration
 * policy.
 */
extern int ppp_key_generate(state *s, int flags);

/*******************************************
 * Combos combining load+lock, some action 
 * and unlock of state db.
 *******************************************/
/**
 * 1. Lock file
 * 2a. Open it
 * 2b. Call ppp_calculate()
 * 2c. Verify that we still can perform authentication
 *     (for example the counter is not bigger than 2^128)
 * 3. Increment counter
 * 4. Save it and unlock
 * 5. Leaves in state non-incremented counter which can be
 *    used for authentication. This counter value can be though
 *    as 'reserved' for this authentication.
 */
extern int ppp_increment(state *s);

/** Lock & Read
 * If zero = 0 then increment failure and recent_failures count.
 * If zero = 1 then clear recent_failures.
 * Store & unlock
 * Does not modify passed state structure
 */
extern int ppp_failures(const state *s, int zero);

/**************************************
 * Passcode/Counter management
 *************************************/
/** Calculate a single passcode using Perfect Paper Passwords
 * algorithm using Key from state. Counter is universal
 * and passed as argument; it may or may not have salt. 
 * if needed salt will be added.
 * char *passcode must have enough place. Minimum 17 bytes.
 */
extern int ppp_get_passcode(const state *s, const num_t counter, char *passcode);

/** Return current passcode. Helper for ppp_get_passcode function. */
extern int ppp_get_current(const state *s, char *passcode);

/** Try to authenticate user; returns 0 on successful authentication.
 * Does not increment counter, just compares with password which would
 * be generated for current passcode (i.e. reserved by ppp_increment call) */
extern int ppp_authenticate(const state *s, const char *passcode);

/** Decode external card number and XY code position into a counter 
 * This function decreases passcard by one so counting starts at '1'.
 * Counter is created with salt included. Result returned in 'passcode'. */
extern int ppp_get_passcode_number(
	const state *s, const num_t passcard,
	num_t *passcode, char column, char row);

/** Adds a salt to given passcode if salt is used.
 * In other words: converts from user supplied passcode
 * into system passcode number. */
extern void ppp_add_salt(const state *s, num_t *passcode);

/** Calculate card parameters and save them in state.  Required by many 
 * (ppp_get_prompt, ppp_verify_range) functions to work.
 * Should be called to update information after any flag, 
 * counter, etc. change */
extern void ppp_calculate(state *s);

/** Print to stdout all acceptable alphabets with IDs */
extern void ppp_alphabet_print(void);

/** Get alphabet string for given ID. 
 * \return On invalid ID returns
 * PPP_ERROR_RANGE and sets alphabet to NULL. If ID is correct and alphabet 
 * allowed by policy returns 0, if ID is correct but alphabet
 * can't be used returns PPP_ERROR_POLICY
 */
extern int ppp_alphabet_get(int ID, const char **alphabet);


/**************************************
 * Warning/Error management 
 *************************************/
/** Returns an ORed mask of warning conditions for state.*/
extern int ppp_get_warning_conditions(const state *s);

/** Take a condition from warning and return it's textual
 * description.
 * and clear this condition from flag. Returns NULL
 * when no conditions are left in argument. */
extern const char *ppp_get_warning_message(const state *s, int *warning);

/** Decode ppp_error (see ppp_common.h for list) */
extern const char *ppp_get_error_desc(int error);

/**************************************
 * State/Policy verification 
 *************************************/
/** Verify that counter (and key) is in correct range 
 * done usually after reading from the state file, when 
 * the data could be maliciously changed */
extern int ppp_verify_range(const state *s);

/** Verify if an alphabet given as ID is correct 
 * and allowed by policy. */
extern int ppp_verify_alphabet(int id);

/** Verify code length */
extern int ppp_verify_code_length(int length);

/** Verify user flags */
extern int ppp_verify_flags(int flags);

/** Verify all parts of user state */
extern int ppp_state_verify(const state *s);


/*******************************************
 * State Getters / Setters
 ******************************************/
/* Setters return '2' if argument is invalid 
 * (because of policy for example), both 
 * setters and getters return '1' if field is invalid 
 * and take the liberty to call assert(0) then. */

/** Get a value out of state and place at "arg" memory location.
 * In some cases this can also be int, not unsigned int.
 * Return value might not be checked if program is debugged
 * with assert.
 */
extern int ppp_get_int(const state *s, int field, unsigned int *arg);

/** Get long number from state. */
extern int ppp_get_mpz(const state *s, int field, num_t *arg);

/** Get character string from state. This sets "arg" memory 
 * to a pointer to state data. This data musn't be altered.
 * Returns 0 on success and 1 if field is incorrect. */
extern int ppp_get_str(const state *s, int field, const char **arg);

/** Int argument setter. options might equal PPP_CHECK_POLICY. */
extern int ppp_set_int(state *s, int field, unsigned int arg, int options);

/** Copy nul-terminated data passed as arg into state.
 * This function checks length of destination buffer
 * and policies (ignores policy if check_policy = 0). 
 * May return 1 if field is wrong (but will rather die).
 * Will return 2 if denied by policy
 * Will return 3 if too big 
 * "options" might equal PPP_CHECK_POLICY.
 */
extern int ppp_set_str(state *s, int field, const char *arg, int options);

/** Setter/getter/checker for flag fields. No policy checking now */
/* Check if flag is set in state, add flag and remove flag. */
extern int ppp_flag_check(const state *s, int flag);
extern void ppp_flag_add(state *s, int flag);
extern void ppp_flag_del(state *s, int flag);

/** Ensure policy and set current SPASS. 
 * Flag might be 0 or PPP_CHECK_POLICY. */
extern char **ppp_spass_set(state *s, const char *spass, int flag);

/** Check if spass given as argument matches one stored 
 * in state. Returns 0 on success */
extern int ppp_spass_validate(const state *s, const char *spass);

#endif
