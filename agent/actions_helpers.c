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

#include <stdio.h>
#include <ctype.h>

/* For ah_get_pass turning echo off */
#include <termios.h>
#include <unistd.h>

#define PPP_INTERNAL 1

/* For options_t struct */
#include "actions.h" 
#include "actions_helpers.h"
#include "security.h"
#include "nls.h"

int ah_init_state(state **s, const options_t *options, int load)
{
	int ret;
	ret = ppp_state_init(s, options->username);
	if (ret != 0) {
		return ret;
	}

	if (load == 0) {
		/* Just initialize */
		return 0;
	}

	ret = ppp_state_load(*s, 0);
	switch (ret) {
	case 0:
		/* All right */
		ret = ppp_state_verify(*s);
		if (ret != 0) {
			printf(_("WARNING: Your state is inconsistent with system policy.\n"
			         "         Fix it or you will be unable to login.\n"
			         "         For details use --info command.\n"));
		}
		return 0;

	default:
		puts(_(ppp_get_error_desc(ret)));
		ppp_state_fini(*s);
		return ret;
	}
}


int ah_fini_state(state **s, int store)
{
	int ret;

	/* We store changes into the file
	 * We don't need to unlock just yet - ppp_fini
	 * will unlock state if it was locked
	 */
	if (store)
		store = PPP_STORE;
	ret = ppp_state_release(*s, store);

	if (ret != 0) {
		printf(_("Error while saving state data. State not changed.\n"));
	}

	ppp_state_fini(*s);
	*s = NULL;

	return ret;
}

int ah_update_flags(options_t *options, state *s, int generation)
{
	int ret;
	cfg_t *cfg = cfg_get();
	assert(options);
	assert(cfg);
	assert(s);

	/* User tries to change salt when he has key generated? */
	if ((generation == 0) && 
	    (options->flag_set_mask & FLAG_SALTED || 
	     options->flag_clear_mask & FLAG_SALTED)) {
		printf(_("Salt configuration can be changed only during key creation.\n"));
		return 1;
	}

	/* Tries to disable/enable himself when not allowed? */
	if (cfg->disabling == CONFIG_DISALLOW) {
		if (options->flag_set_mask & FLAG_DISABLED ||
		    options->flag_clear_mask & FLAG_DISABLED) {
			printf(_("Changing a \"disable\" flag disallowed by policy.\n"));
			return 1;
		}
	}

	/* Check policy of salt */
	switch (cfg->salt) {
	case CONFIG_DISALLOW:
		if (options->flag_set_mask & FLAG_SALTED) {
			printf(_("Policy disallows salted keys.\n"));
			return 1;
		}
		break;
	case CONFIG_ENFORCE:
		if (options->flag_clear_mask & FLAG_SALTED) {
			printf(_("Policy enforces salted keys.\n"));
			return 1;
		}
		break;
	case CONFIG_ALLOW:
	default:
		break;
	}

	/* Check policy of show */
	switch (cfg->show) {
	case CONFIG_DISALLOW:
		if (options->flag_set_mask & FLAG_SHOW) {
			printf(_("Policy disallows showing entered passcodes.\n"));
			return 1;
		}
		break;
	case CONFIG_ENFORCE:
		if (options->flag_clear_mask & FLAG_SHOW) {
			printf(_("Policy enforces entered passcode visibility.\n"));
			return 1;
		}
		break;
	case CONFIG_ALLOW:
	default:
		break;
	}

	/* Copy all user-selected values to state
	 * but check if they match policy */

	/* Length of contact/label is ensured in process_cmd_line */
	if (options->contact) {
		ret = ppp_set_str(s, PPP_FIELD_CONTACT, options->contact,
				  security_is_privileged() ? 0 : PPP_CHECK_POLICY);

		switch (ret) {
		case PPP_ERROR_ILL_CHAR:
			printf(_("Contact contains illegal characters.\n"
			         "Only alphanumeric + \" -+.@_*\" are allowed.\n"));
			return ret;

		case PPP_ERROR_TOO_LONG:
			printf(_("Contact can't be longer than %d "
			         "characters\n"), STATE_CONTACT_SIZE-1);
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Contact changing denied by policy.\n"));
			return ret;

		case 0:
			break;
		default:
			printf(_("Unexpected error while setting contact information.\n"));
			return 1;
		}
	}

	if (options->label) {
		ret = ppp_set_str(s, PPP_FIELD_LABEL, options->label,
				  security_is_privileged() ? 0 : PPP_CHECK_POLICY);
		switch (ret) {
		case PPP_ERROR_ILL_CHAR:
			printf(_("Label contains illegal characters.\n"
			         "Only alphanumeric + \" -+.@_*\" are allowed.\n"));
			return ret;

		case PPP_ERROR_TOO_LONG:
			printf(_("Label can't be longer than %d "
			       "characters\n"), STATE_LABEL_SIZE-1);
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Label changing denied by policy.\n"));
			return ret;

		case 0:
			break;

		default:
			printf(_("Unexpected error while setting label information.\n"));
			return 1;
		}
	}

	/* Code length + alphabet */
	if (options->set_codelength != -1) {
		ret = ppp_set_int(s, PPP_FIELD_CODE_LENGTH, options->set_codelength, 1);
		switch (ret) {
		case PPP_ERROR_RANGE:
			printf(_("Passcode length must be between 2 and 16.\n"));
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Setting passcode length denied by policy.\n"));
			return ret;
		case 0:
			break;
		default: 
			printf(_("Unexpected error while setting code length.\n"));
			return 1;
		}

		printf(_("Warning: Changing codelength invalidates "
		       "already printed passcards.\n"
		       "         If you like, you can switch back "
		       "to your previous settings.\n\n"));
	}

	if (options->set_alphabet != -1) {
		ret = ppp_set_int(s, PPP_FIELD_ALPHABET, options->set_alphabet, 1);
		switch (ret) { 
		case PPP_ERROR_RANGE:
			printf(_("Illegal alphabet ID specified. See "
			       "-f alphabet-list\n"));
			return ret;
		case PPP_ERROR_POLICY:
			printf(_("Alphabet denied by policy. See "
			       "-f alphabet-list\n"));
			return ret;
		case 0:
			
			break;
		default:
			printf(_("Unexpected error while setting code length.\n"));
			return 1;
		} 

		printf(_("Warning: Changing alphabet invalidates "
		       "already printed passcards.\n"
		       "         If you like, you can switch back "
		       "to your previous settings.\n\n"));
	}

	/* Change flags */
	ppp_flag_add(s, options->flag_set_mask);
	ppp_flag_del(s, options->flag_clear_mask);
	return 0;
}

