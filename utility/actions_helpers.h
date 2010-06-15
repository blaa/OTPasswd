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

enum {
	QUERY_YES=0,
	QUERY_NO=2,
	QUERY_OBSCURE=1
};

/* Ask user once and return _YES, _NO or _OBSCURE */
int ah_yes_or_no(const char *msg);

/* Ask user until he gives up and answers. */
int ah_enforced_yes_or_no(const char *msg);

/* Read password without echoing characters to console */
const char *ah_get_pass(void);

/* Show user flags */
int ah_show_flags(agent *a);

/* Show user state (current codes/cards) */
int ah_show_state(agent *a);

/* Show user key/counter */
void ah_show_keys(agent *a);

#if 0

/* Check if passcard is in range */
int ah_is_passcard_in_range(const state *s, const num_t passcard);

/* Check if passcode is in range */
int ah_is_passcode_in_range(const state *s, const num_t passcard);


/* Update state flags. Checks policy. If generation is 1 we allow salt changes. */
int ah_update_flags(options_t *options, state *s, int generation);

/* Parse code specification and store resulting data in arguments */
int ah_parse_code_spec(const state *s, const char *spec, num_t *passcard, num_t *passcode);

#endif 

#endif
