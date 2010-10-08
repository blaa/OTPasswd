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
#include <unistd.h> /* sleep */

/* libotp interface */
#include "ppp.h"

/* PAM declarations */
#include <pam_modules.h>
#include "pam_helpers.h"

/** Entry point for authentication */
PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* Static password failure delay */
	const int spass_delay = 2;

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

	/* Have user entered OOB in this session? */
	int oob_sent = 0;
	
	/* User messages */
	const char *oob_msg = "Out-of-band message sent.";
	const char *oob_already_msg = "Out-of-band message already sent.";

	/* Counters required for login algorithm */
	int first_try = 1;
	int dont_increment = 0; /* Do not increment if previous prompt was for OOB */
	int tries;


	/* Perform initialization:
	 * parse options, start logging, initialize state,
	 */
	retval = ph_init(pamh, flags, argc, argv, &s, &username);
	if (retval != 0)
		return retval;

	cfg = cfg_get();

	if (cfg->pam_spass_require == CONFIG_ENABLED) {
		/* Before we will enter passcode loop ask user for his
		 * static password. As this is supposed to be used instead
		 * of unix password we behave similarly. We ask questions
		 * even if used doesn't have state and don't tell anything. */
		int loaded = 0;
		retval = ppp_state_load(s, PPP_DONT_LOCK);
		if (retval == 0)
			loaded = 1;
		else
			print(PRINT_NOTICE,
			      "unable to read state when "
			      "asking for static password; user=%s error=%d\n",
			      username, retval);

		if (ph_validate_spass(pamh, loaded ? s : NULL, username) != 0) {
			sleep(spass_delay);
			return PAM_AUTH_ERR;
		}
	}


	first_try = 1;
	dont_increment = 0;
	for (tries = 0; tries < (cfg->pam_retry == 0 ? 1 : cfg->pam_retries);) {
		if (first_try || cfg->pam_retry == 1) {
			/* First time or we are retrying while changing the passcode */
			first_try = 0;
			if (dont_increment) 
				dont_increment = 0;
			else {
				retval = ph_increment(pamh, username, s);
				if (retval != 0)
					goto cleanup;

				/* Generate fresh prompt */
				retval = ppp_get_str(s, PPP_FIELD_PROMPT, &prompt);
				if (retval != 0 || !prompt) {
					print(PRINT_ERROR, "error while generating prompt; user=%s", 
					      username);
					retval = PAM_AUTH_ERR;
					goto cleanup;
				}
			}
		}

		/* If user configurated OOB to be send
		 * all the time - sent it */
		if (cfg->pam_oob == OOB_ALWAYS) {
			ph_oob_send(pamh, s, username);
		}

		retval = PAM_AUTH_ERR;

		/* State question about passcode. User might
		 * request OOB by answering with '.'. If so
		 * we perform OOB and restate question */
		resp = ph_query_user(pamh,
				     ppp_flag_check(s, FLAG_SHOW),
				     prompt);

		if (!resp) {
			/* No response? */
			print(PRINT_NOTICE, "no response from user during auth; user=%s\n", 
			      username);
			goto cleanup;
		}

		/* Hook up OOB request */
		if (strcmp(resp->resp, ".") == 0) {
			/* Drop reply. We will most probably 
			 * restate question about passcode. */
			ph_drop_response(resp);

			/* Was it already sent? */
			if (oob_sent) {
				/* if so - ignore prompt with message */
				ph_show_message(pamh, oob_already_msg, username);
				dont_increment = 1;
				continue;
			}

			/* Only if not already sent in this session. */
			switch (cfg->pam_oob) {
			case OOB_REQUEST:
				if (ph_oob_send(pamh, s, username) == 0) {
					ph_show_message(pamh, oob_msg, username);
					oob_sent = 1;
				}
				break;
				
			case OOB_SECURE_REQUEST:
				if (ph_validate_spass(pamh, s, username) == 0) {
					if (ph_oob_send(pamh, s, username) == 0) {
						ph_show_message(pamh, oob_msg, username);
						oob_sent = 1;
					}
				} else {
					/* Ensure attacker doesn't have 
					 * infinite tries of static pass */
					sleep(spass_delay);
					tries++;
				}
				break;
			default:
				print(PRINT_ERROR, "Internal error: "
				      "Invalid option read from config file.\n");
				assert(0);
				retval = PAM_AUTH_ERR;
				goto cleanup;
			}

			/* Continue, so the user is restated question about passcode */
			dont_increment = 1;
			continue;
		}


		/* Count this try */
		tries++;

		if (ppp_authenticate(s, resp[0].resp) == 0) {
			/* Authenticated */
			ph_drop_response(resp);

			/* Correctly authenticated */
			retval = PAM_SUCCESS;

			print(PRINT_WARN,
			      "accepted otp authentication; user=%s\n", username);
			goto cleanup;
		}

		ph_drop_response(resp);

		/* Increment count of failures */
		retval = ppp_failures(s, 0);
		if (retval != 0) {
			print(PRINT_WARN, "unable to increment failure count; user=%s", 
			      username);
		}

		/* Error during authentication */
		retval = PAM_AUTH_ERR;

		print(PRINT_WARN, 
		      "authentication failure; user=%s; try=%d/%d\n",
		      username, tries+1, cfg->pam_retries);
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
	int release_flags = 0;

	/* OTP State */
	state *s = NULL;

	/* Username */
	const char *username = NULL;

	/* User warning conditions */
	int err;

	/* Initialize */
	retval = ph_init(pamh, flags, argc, argv, &s, &username);
	if (retval != 0) {
		print(PRINT_WARN, "error while initializing PPP; user=%s\n", username);
		return retval;
	}

	print(PRINT_NOTICE, "session entrance; user=%s\n", username);

	if (ppp_state_load(s, 0) != 0)
		goto exit;

	print(PRINT_NOTICE, "state loaded; user=%s\n", username);

	err = ppp_get_warning_conditions(s);
	if (err == 0) {
		/* No warnings! */
		print(PRINT_NOTICE, "no warning to print; user=%s\n", username);
		goto cleanup;
	}


	{
		const char *msg = NULL;
		int err_copy = err;
		char buff_msg[300] = {0};
		int len;

		while ((msg = ppp_get_warning_message(s, &err_copy)) != NULL) {
			/* Generate message */

			len = snprintf(buff_msg, sizeof(buff_msg), "*** OTP Warning: %s", msg);
			if (len < 10) {
				print(PRINT_ERROR, "internal error: strange sprintf error; user=%s\n", username);
				goto cleanup;
			}

			ph_show_message(pamh, buff_msg, username);
		}
	}

	/* Have we printed warning about recent failures? */
	if (err & PPP_WARN_RECENT_FAILURES) {
		if (ppp_set_int(s, PPP_FIELD_RECENT_FAILURES, 0, PPP_CHECK_POLICY) != 0)
			print(PRINT_WARN, "unable to clear recent failures; user=%s\n", username);
		release_flags = PPP_STORE;
	}

cleanup:
	ppp_state_release(s, PPP_UNLOCK | release_flags);
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
