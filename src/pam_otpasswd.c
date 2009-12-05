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

#include <syslog.h>

#include "print.h"
#include "ppp.h"

static void _show_message(pam_handle_t *pamh, int flags, const char *msg)
{
	/* Required for communication with user */
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;

	/* Initialize conversation function */
	pam_get_item(pamh, PAM_CONV, (const void **)&conversation);

	if (!(flags & PAM_SILENT)) {
		/* Tell why */
		message.msg_style = PAM_TEXT_INFO;
		message.msg = msg;
		conversation->conv(
			1,
			(const struct pam_message**)&pmessage,
			&resp, conversation->appdata_ptr);
		if (resp)
			_pam_drop_reply(resp, 1);
	}

}

static int _handle_load(pam_handle_t *pamh, int flags, int enforced, state *s)
{
	const char enforced_msg[] = "otpasswd: Key not generated, unable to login.";
	const char lock_msg[] = "otpasswd: Unable to lock user state file.";
	const char numspace_msg[] =
		"otpasswd: Passcode counter overflowed or state "
		"file corrupted. Regenerate key.";

	switch (ppp_increment(s)) {
	case 0:
		/* Everything fine */
		return 0;
		
	case STATE_NUMSPACE:
		/* Strange error, might happen, but, huh! */
		_show_message(pamh, flags, numspace_msg);
		return PAM_AUTH_ERR;
		
	case STATE_LOCK_ERROR:
		_show_message(pamh, flags, lock_msg);
		return PAM_AUTH_ERR;

	case STATE_DOESNT_EXISTS:
		if (enforced == 0) {
			/* Not enforced - ignore */
			return PAM_IGNORE;
		} else {
			_show_message(pamh, flags, enforced_msg);
		}
		
		/* Fall-throught */
		
	default: /* Any other problem - error */
		return PAM_AUTH_ERR;
	}

}

static struct pam_response *pam_query_user(pam_handle_t *pamh, int flags, int show, const char *prompt, const state *s)
{
	/* Required for communication with user */
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;

	/* Initialize conversation function */
	pam_get_item(pamh, PAM_CONV, (const void **)&conversation);

	/* Echo on if enforced by "show" option or enabled by user
	 * and not disabled by "noshow" option 
	 */
	if ((show == 2) || (show == 1 && (ppp_is_flag(s, FLAG_SHOW)))) {
		message.msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		message.msg_style = PAM_PROMPT_ECHO_OFF;
	}
	
	message.msg = prompt;
	conversation->conv(1, (const struct pam_message **)&pmessage,
			   &resp, conversation->appdata_ptr);

	return resp;
}

typedef struct {
	/* Enforced makes any user without an .otpasswd config
	 * fail to login */
	int enforced;

	/* Do we allow dont-skip? 0 - yes */
	int secure;

	/* Turns on increased debugging (into syslog) */
	int debug;		

	/* 0 - no retry 
	 * 1 - retry with new passcode
	 * 2 - retry with the same passcode
	 * Will always retry 3 times...
	 */
	int retry;

	/* Shall we echo entered passcode?
	 * 1 - user selected
	 * 0 - (noshow) echo disabled
	 * 2 - (show) echo enabled
	 */
	int show;
} options;

static int _parse_options(options *opt, int argc, const char **argv)
{
	/* Default values */
	opt->retry = opt->enforced = opt->secure = opt->debug = 0;
	opt->show = 1;

	for (; argc-- > 0; argv++) {
		if (strcmp("enforced", *argv) == 0)
			opt->enforced = 1;
		else if (strcmp("secure", *argv) == 0)
			opt->secure = 1;
		else if (strcmp("show", *argv) == 0)
			opt->show = 2;
		else if (strcmp("noshow", *argv) == 0)
			opt->show = 0;
		else if (strcmp("debug", *argv) == 0)
			opt->debug = 1;
		else if (sscanf(*argv, "retry=%d", &opt->retry) == 1) {
			if (opt->retry < 0 || opt->retry > 2) {
				print(PRINT_ERROR, "Invalid retry parameter (valid values = 0, 1, 2)");
				return PAM_AUTH_ERR;
			}
		} else {
			print(PRINT_ERROR, "Invalid parameter %s\n", *argv);
			return PAM_AUTH_ERR;
		}
	}
	if (opt->debug) {
		print(PRINT_NOTICE, "otpasswd config: enforced=%d show=%d secure=%d retry=%d\n",
		      opt->enforced, opt->show, opt->secure, opt->retry);
	}
	return 0;
}

/* Initialization stuff */
static int _init(pam_handle_t *pamh, int argc, const char **argv, options *opt, state **s)
{
	/* User info from PAM */
	const char *user = NULL;
	
	int retval;

	/* Bootstrap logging */
	print_init(PRINT_NOTICE, 0, 1, NULL);

	/* Parse options */
	retval = _parse_options(opt, argc, argv);
	print_fini(); /* Close bootstrapped logging */
	if (retval != 0) {
		return retval;
	}

	/* Initialize internal debugging */
	if (opt->debug) {
		print_init(PRINT_NOTICE, 0, 1, "/tmp/otpasswd_dbg");
		print(PRINT_NOTICE, "otpasswd started\n");
	} else
		print_init(PRINT_ERROR, 0, 1, NULL);

	/* We must know where to look for state file */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS && user) {
		print(PRINT_ERROR, "pam_get_user %s", pam_strerror(pamh,retval));
		goto error;
	}

	if (user == NULL || *user == '\0') {
		print(PRINT_ERROR, "empty_username", pam_strerror(pamh,retval));
		goto error;
	}

	/* Initialize state with given username */
	if (ppp_init(s, user) != 0) {
		/* This will fail if we're unable to locate home directory */
		goto error;
	}

	/* All ok */
	return 0;
error:
	print_fini();
	return PAM_USER_UNKNOWN;
}

/* PAM_AUTH_ERR, PAM_CRED_INSUFFICIENT PAM_AUTHINFO_UNAVAIL PAM_USER_UNKNOWN PAM_MAXTRIES */
/* PAM_TEXT_INFO PAM_ERROR_MSG PAM_PROMPT_ECHO_ON PAM_RPOMPT_ECHO_OFF */
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
	retval = _init(pamh, argc, argv, &opt, &s);
	if (retval != 0)
		return retval;
     
	/* Retry = 0 - do not retry, 1 - with changing passcodes */
	int tries;
	for (tries = 0; tries < (opt.retry == 0 ? 1 : 3); tries++) {
		if (tries == 0 || opt.retry == 1) {
			/* First time or we are retrying while changing the password */
			retval = _handle_load(pamh, flags, opt.enforced, s);
			if (retval != 0)
				goto cleanup;

			/* Generate prompt */
			ppp_calculate(s);
			prompt = ppp_get_prompt(s);
			if (!prompt) {
				print(PRINT_ERROR, "Error while generating prompt\n");
				retval = PAM_AUTH_ERR;
				goto cleanup;
			}
		}

		resp = pam_query_user(pamh, flags, opt.show, prompt, s);

		retval = PAM_AUTH_ERR; 
		if (!resp) {
			/* No response? */
			goto cleanup;
		}

		if (ppp_authenticate(s, resp[0].resp) == 0) {
			_pam_drop_reply(resp, 1);
			
			/* Correctly authenticated */
			retval = PAM_SUCCESS;
			goto cleanup;
		}

		/* Error during authentication */
		if (opt.retry == 0 && opt.secure == 0 && ppp_is_flag(s, FLAG_SKIP) == 0) {
			/* Decrement counter */
			retval = ppp_decrement(s);
			if (retval != 0) {
				retval = PAM_AUTH_ERR;
				print(PRINT_WARN, "Error while decrementing\n");
				goto cleanup;
			}
		}
		retval = PAM_AUTH_ERR;
	}

cleanup:
	ppp_fini(s);
	print_fini();
	return retval;
}

PAM_EXTERN int pam_sm_open_session(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
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
