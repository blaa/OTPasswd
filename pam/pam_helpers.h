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

enum {
	OOB_DISABLED = 0,
	OOB_REQUEST = 1,
	OOB_SECURE_REQUEST = 2,
	OOB_ALWAYS = 3
};

extern int ph_parse_module_options(options *opt, int argc, const char **argv);

extern int ph_out_of_band(const options *opt, state *s);

extern void ph_show_message(pam_handle_t *pamh, int flags, const char *msg);

extern int ph_handle_load(pam_handle_t *pamh, int flags, int enforced, state *s);

extern struct pam_response *ph_query_user(
	pam_handle_t *pamh, int flags, int show,
	const char *prompt, const state *s);

/* initialization stuff */
extern int ph_init(pam_handle_t *pamh, int argc, const char **argv, options *opt, state **s);

#endif
