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

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#define _PAM_EXTERN_FUNCTIONS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libotp interface */
#include "ppp.h"

/* PAM declarations */
#include <pam_modules.h>
#include "pam_macros.h"
#include "pam_helpers.h"

/* Entry point for authentication */
PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* Prompt to ask user */
	const char *prompt = NULL;

	/* Required for communication with user */
	struct pam_response *resp = NULL;

	/* OTP State */
	state *s = NULL;

	/* Parameters */
	cfg_t *cfg = NULL;

	/* Username */
	const char *username = NULL;

	/* Perform initialization:
	 * parse options, start logging, initialize state,
	 */
	retval = ph_init(pamh, flags, argc, argv, &cfg, &s, &username);
	if (retval != 0)
		return retval;
	
	/* Retry = 0 - do not retry, 1 - with changing passcodes */
	int tries;
	for (tries = 0; tries < (cfg->retry == 0 ? 1 : cfg->retries); tries++) {
		if (tries == 0 || cfg->retry == 1) {
			/* First time or we are retrying while changing the password */
			retval = ph_increment(pamh, cfg, username, s);
			if (retval != 0)
				goto cleanup;

			/* Generate prompt */
			retval = ppp_get_str(s, PPP_FIELD_PROMPT, &prompt);
			if (retval != 0 || !prompt) {
				print(PRINT_ERROR, "Error while generating prompt\n");
				retval = PAM_AUTH_ERR;
				goto cleanup;
			}
		}

		/* If user configurated OOB to be send
		 * all the time - sent it */
		if (cfg->oob == OOB_ALWAYS) {
			ph_out_of_band(cfg, s);
		}

		resp = ph_query_user(pamh, flags,
				     ppp_flag_check(s, FLAG_SHOW),
				     prompt, s);

		retval = PAM_AUTH_ERR;
		if (!resp) {
			/* No response? */
			print(PRINT_NOTICE, "No response from user during auth.\n");
			goto cleanup;
		}

		/* We must free resp after this point ourselves. */

		/* Hook up OOB request */
		if (strcmp(resp[0].resp, ".") == 0) {
			switch (cfg->oob) {
			case OOB_REQUEST:
				ph_out_of_band(cfg, s);

				/* Drop reply + restate question about passcode */
				_pam_drop_reply(resp, 1);
				resp = ph_query_user(pamh, flags, ppp_flag_check(s, FLAG_SHOW), prompt, s);

				if (!resp) {
					/* No response? */
					print(PRINT_NOTICE, "No response from user during auth.\n");
					goto cleanup;
				}

				break;
			case OOB_SECURE_REQUEST:
				/* TODO: To be implemented */
				break;
			}
		}

		if (ppp_authenticate(s, resp[0].resp) == 0) {
			/* Authenticated */
			_pam_drop_reply(resp, 1);

			/* Correctly authenticated */
			retval = PAM_SUCCESS;

			print(PRINT_WARN,
			      "Accepted otp authentication for user %s\n",
			      username);
			goto cleanup;
		}

		_pam_drop_reply(resp, 1);

		/* Increment count of failures */
		retval = ppp_failures(s, 0);
		if (retval != 0) {
			print(PRINT_WARN, "Unable to increment failure count\n");
		}

		/* Error during authentication */
		retval = PAM_AUTH_ERR;

		print(PRINT_WARN, 
		      "Authentication failure; user=%s; try=%d/%d\n",
		      username, tries+1, cfg->retries);
	}

cleanup:
	ph_fini(s);
	return retval;
}

PAM_EXTERN int pam_sm_open_session(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* Should we store state after printing? */
	int store = 0;

	/* OTP State */
	state *s;

	/* Parameters */
	cfg_t *cfg;

	/* Username */
	const char *username;

	/* Initialize */
	retval = ph_init(pamh, flags, argc, argv, &cfg, &s, &username);
	if (retval != 0)
		return retval;

	print(PRINT_NOTICE, "(session) entrance\n");

	if (ppp_load(s) != 0)
		goto exit;

	print(PRINT_NOTICE, "(session) state loaded\n");

	const int err = ppp_get_warning_conditions(s);
	if (err == 0) {
		/* No warnings! */
		print(PRINT_NOTICE, "(session) no warning to be printed\n");
		goto cleanup;
	}


	const char *msg;
	int err_copy = err;
	while ((msg = ppp_get_warning_message(s, &err_copy)) != NULL) {
		/* Generate message */
		char buff_msg[300];
		int len;
		
		len = snprintf(buff_msg, sizeof(buff_msg), "*** OTPasswd Warning: %s", msg);
		if (len < 10) {
			print(PRINT_ERROR, "(session) sprintf error\n");
			goto cleanup;
		}
		
		ph_show_message(pamh, cfg, buff_msg);
	}

	/* Have we printed warning about recent failures? */
	if (err & PPP_WARN_RECENT_FAILURES) {
		if (ppp_set_int(s, PPP_FIELD_RECENT_FAILURES, 0, PPP_CHECK_POLICY) != 0)
			print(PRINT_WARN, "Unable to clear recent failures\n");
		store = 1;
	}


cleanup:
	ppp_release(s, store, 1);
exit:
	ph_fini(s);

	/* Ignore us, even if we fail. */
	return PAM_IGNORE;
}


/* Ignored/not-implemented functions */
PAM_EXTERN int pam_sm_setcred(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	 return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* Initialization struct */
struct pam_module _pam_permit_modstruct = {
	"otpasswd",
	otp_authenticate,
	otp_setcred,
	NULL,
	otp_open_session,
	otp_close_session,
	NULL
};

#endif
