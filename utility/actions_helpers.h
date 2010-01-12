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

#ifndef _ACTIONS_HELPERS_H_
#define _ACTIONS_HELPERS_H_

#include <gmp.h>
#include "ppp.h"

enum {
	QUERY_YES=0,
	QUERY_NO=2,
	QUERY_OBSCURE=1
};

/* Secure init/load state. Should be used everywhere
 * when state would be locked anyway (we can't block execution
 * after this function). */
int ah_init_state(state **s, const options_t *options, int load);

/* Finish anything started by "_load_state" */
int ah_fini_state(state **s, int store);

/* Ask user once and return _YES, _NO or _OBSCURE */
int ah_yes_or_no(const char *msg);

/* Ask user until he gives up and answers. */
int ah_enforced_yes_or_no(const char *msg);

/* Check if passcard is in range */
int ah_is_passcard_in_range(const state *s, const mpz_t passcard);

/* Check if passcode is in range */
int ah_is_passcode_in_range(const state *s, const mpz_t passcard);

/* Show user flags */
void ah_show_flags(const state *s);

/* Show user key/counter */
void ah_show_keys(const state *s);

/* Update state flags. Checks policy. If generation is 1 we allow salt changes. */
int ah_update_flags(options_t *options, state *s, int generation);

/* Parse code specification and store resulting data in arguments */
int ah_parse_code_spec(const state *s, const char *spec, mpz_t passcard, mpz_t passcode);



const char *ah_get_pass(void);



#endif
