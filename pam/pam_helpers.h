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

#ifndef _PAM_HELPERS_
#define _PAM_HELPERS_

#include "config.h"

/* Parse module options and modify options accordingly */
extern int ph_parse_module_options(int flags, int argc, const char **argv, options *opt);

/* Send out of band message by calling external script.
 * s parameter is generally const, but child will 
 * clean it up */
extern int ph_out_of_band(const options *opt, state *s);

/* Display user a message; disabled if in "silent mode" */
extern void ph_show_message(pam_handle_t *pamh, const options *opt, const char *msg);

/* Load state, increment save, handle errors if any */
extern int ph_state_increment(pam_handle_t *pamh, int flags, int enforced, 
			      const options *opt, state *s);

/* Function which automates a bit talking with user */
extern struct pam_response *ph_query_user(
	pam_handle_t *pamh, int flags, int show,
	const char *prompt, const state *s);

/* Function performing PAM initialization */
extern int ph_init(pam_handle_t *pamh, int flags, int argc, const char **argv, options **opt, state **s);

/* Deinitialize whatever ph_init initialized */
extern void ph_fini(state *s);

#endif
