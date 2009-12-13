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

#define PAM_SM_AUTH
#define PAM_SM_SESSION
//#define PAM_SM_ACCOUNT
//#define PAM_SM_PASSWORD
#define _PAM_EXTERN_FUNCTIONS

#include <_pam_macros.h>
#include <pam_modules.h>
#include <pam_misc.h>
#include <pam_ext.h>

#include "print.h"
#include "ppp.h"
#include "pam_helpers.h"


/* Entry point for authentication */
PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* Prompt to ask user */
	const char *prompt = NULL;

	/* OTP State */
	state *s;

	/* Required for communication with user */
	struct pam_response *resp = NULL;

	/* Parameters */
	options opt;

	/* Perform initialization:
	 * parse options, start logging, initialize state
	 */
	retval = ph_init(pamh, argc, argv, &opt, &s);
	if (retval != 0)
		return retval;

	/* Retry = 0 - do not retry, 1 - with changing passcodes */
	int tries;
	for (tries = 0; tries < (opt.retry == 0 ? 1 : 3); tries++) {
		if (tries == 0 || opt.retry == 1) {
			/* First time or we are retrying while changing the password */
			retval = ph_handle_load(pamh, flags, opt.enforce, s);
			if (retval != 0)
				goto cleanup;

			/* Generate prompt */
			ppp_calculate(s);
			prompt = ppp_get_prompt(s);
			if (!prompt) {
				(void)print(PRINT_ERROR, "Error while generating prompt\n");
				retval = PAM_AUTH_ERR;
				goto cleanup;
			}
		}

		/* If user configurated OOB to be send
		 * all the time - sent it */
		if (opt.oob == OOB_ALWAYS) {
			ph_out_of_band(&opt, s);
		}

		resp = ph_query_user(pamh, flags, opt.show, prompt, s);

		retval = PAM_AUTH_ERR;
		if (!resp) {
			/* No response? */
			(void)print(PRINT_NOTICE, "No response from user during auth.\n");
			goto cleanup;
		}

		/* Hook up OOB request */
		if (strlen(resp[0].resp) == 1 && resp[0].resp[0] == '.') {
			switch (opt.oob) {
			case OOB_REQUEST:
				ph_out_of_band(&opt, s);
				/* Restate question about passcode */
				_pam_drop_reply(resp, 1);
				resp = ph_query_user(pamh, flags, opt.show, prompt, s);
				break;
			case OOB_SECURE_REQUEST:
				/* TODO: To be implemented */
				break;
			}
		}

		if (ppp_authenticate(s, resp[0].resp) == 0) {
			_pam_drop_reply(resp, 1);

			/* Correctly authenticated */
			retval = PAM_SUCCESS;
			(void)print(PRINT_NOTICE, "Authentication succeded\n");
			goto cleanup;
		}

		/* Error during authentication */
		if (opt.retry == 0 && opt.secure == 0 && ppp_is_flag(s, FLAG_SKIP) == 0) {
			/* Decrement counter */
			retval = ppp_decrement(s);
			if (retval != 0) {
				retval = PAM_AUTH_ERR;
				(void)print(PRINT_WARN, "Error while decrementing\n");
				goto cleanup;
			}
		}
		retval = PAM_AUTH_ERR;
	}

	(void)print(PRINT_NOTICE, "Authentication failed\n");

cleanup:
	ppp_fini(s);
	(void)print(PRINT_NOTICE, "otpasswd finished\n");
	print_fini();
	return retval;
}

PAM_EXTERN int pam_sm_open_session(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* OTP State */
	state *s;

	/* Parameters */
	options opt;

	/* Initialize */
	retval = ph_init(pamh, argc, argv, &opt, &s);
	if (retval != 0)
		return retval;

	(void)print(PRINT_NOTICE, "(session) entrance\n");

	if (ppp_load(s) != 0)
		goto exit;

	(void)print(PRINT_NOTICE, "(session) state loaded\n");

	int err = ppp_get_warning_condition(s);
	if (err == 0) {
		/* No warnings! */
		(void)print(PRINT_NOTICE, "(session) no warning to be printed\n");
		goto cleanup;
	}

	const char *msg = ppp_get_warning_message(err);

	if (!msg) {
		/* Should never happen */
		(void)print(PRINT_NOTICE, "(session) no warning returned\n");
		goto cleanup;
	}

	/* Generate message */
	char buff_msg[200], buff_ast[200];
	int len, i;

	len = snprintf(buff_msg, sizeof(buff_msg), "* WARNING: %s *", msg);
	if (len < 10) {
		(void)print(PRINT_ERROR, "(session) sprintf error\n");
		goto cleanup;
	}

	for (i=0; i<len && i < sizeof(buff_ast)-1; i++)
		buff_ast[i] = '*';
	buff_ast[i] = '\0';
	/* FIXME: musn't we use single ph_show_message? */
	ph_show_message(pamh, flags, buff_ast);
	ph_show_message(pamh, flags, buff_msg);
	ph_show_message(pamh, flags, buff_ast);

cleanup:
	ppp_release(s, 0, 1); /* Unlock, do not store */
exit:
	ppp_fini(s);

	(void)print(PRINT_NOTICE, "otpasswd finished\n");
	print_fini();

	/* Ignore us, even if we fail. */
	return PAM_SUCCESS;
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
