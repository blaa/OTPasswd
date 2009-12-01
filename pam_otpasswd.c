#define PAM_SM_AUTH
//#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
//#define PAM_SM_PASSWORD
#define _PAM_EXTERN_FUNCTIONS

#include <_pam_macros.h>
#include <pam_modules.h>
#include <pam_misc.h>
#include <pam_ext.h>

#include <syslog.h>


#include "state.h"

#include "print.h"
#include "state.h"
#include "ppp.h"

static void pam_show_message(pam_handle_t *pamh, int flags, const char *msg)
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

static int pam_handle_load(pam_handle_t *pamh, int flags, int enforced, state *s)
{
	const char enforced_msg[] = "OTP not configured, unable to login.";
	const char numspace_msg[] =
		"Passcode counter overflowed or state "
		"file corrupted. Regenerate key.";

	switch (ppp_load_increment(s)) {
	case 0:
		/* Everything fine */
		return 0;
		
	case STATE_NUMSPACE:
		/* Strange error, might happen, but, huh! */
		pam_show_message(pamh, flags, numspace_msg);
		return PAM_AUTH_ERR;
		
	case STATE_DOESNT_EXISTS:
		if (enforced == 0) {
			/* Not enforced - ignore */
			return PAM_IGNORE;
		} else {
			pam_show_message(pamh, flags, enforced_msg);
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
	if ((show == 2) || (show == 1 && (s->flags & FLAG_SHOW))) {
		message.msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		message.msg_style = PAM_PROMPT_ECHO_OFF;
	}
	
	message.msg = prompt;
	conversation->conv(1, (const struct pam_message **)&pmessage,
			   &resp, conversation->appdata_ptr);

	return resp;
}


/* PAM_AUTH_ERR, PAM_CRED_INSUFFICIENT PAM_AUTHINFO_UNAVAIL PAM_USER_UNKNOWN PAM_MAXTRIES */
/* PAM_TEXT_INFO PAM_ERROR_MSG PAM_PROMPT_ECHO_ON PAM_RPOMPT_ECHO_OFF */
PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;

	/* User info from PAM */
	const char *user = NULL;

	/* Prompt to ask user */
	const char *prompt = NULL;

	/* OTP State */
	state s;

	/* Required for communication with user */
	struct pam_response *resp = NULL;

	/* Module options */

	/* Enforced makes any user without an .otpasswd config
	 * fail to login */
	int enforced = 0;	/* Do we enforce OTP logons? */
	int secure = 0;		/* Do we allow dont-skip? 0 - yes */
	int debug = 0;		/* Turns on increased debugging (into syslog) */
	int retry = 0;		/* 0 - no retry 
				 * 1 - retry with new passcode
				 * 2 - retry with the same passcode
				 * Will always retry 3 times...
				 */
	int show = 1;		/* Shall we echo entered passcode?
				 * 1 - user selected
				 * 0 - (noshow) echo disabled
				 * 2 - (show) echo enabled
				 */
	/* TODO: retry option */
	for (; argc-- > 0; argv++) {
		if (strcmp("enforced", *argv) == 0)
			enforced = 1;
		else if (strcmp("secure", *argv) == 0)
			secure = 1;
		else if (strcmp("show", *argv) == 0)
			show = 2;
		else if (strcmp("noshow", *argv) == 0)
			show = 0;
		else if (strcmp("debug", *argv) == 0)
			debug = 1;
		else if (sscanf(*argv, "retry=%d", &retry) == 1) {
			if (retry < 0 || retry > 2) {
				D(("invalid retry parameter (valid values = 0, 1, 2)"));
				return PAM_AUTH_ERR;
			}
		}
	}

	/* Initialize internal debugging */
	if (debug) {
		print_init(PRINT_NOTICE, 0, 1, "/tmp/otpasswd_dbg");
		print(PRINT_NOTICE, "LOG FILE OPENED FROM PAM\n");
	} else
		print_init(PRINT_ERROR, 0, 1, NULL);

	/* We must know where to look for state file */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS && user) {
		D(("pam_get_user %s", pam_strerror(pamh,retval)));
		pam_syslog(pamh, LOG_ERR, "bad username [%s]", user);
		return PAM_USER_UNKNOWN;
	}

	if (user == NULL || *user == '\0') {
		pam_syslog(pamh, LOG_ERR, "empty username");
		return PAM_USER_UNKNOWN;
	}

	/* Initialize state with given username, and default config file */
	if (state_init(&s, user, NULL) != 0) {
		/* This will fail if we're unable to locate home directory */
		return PAM_USER_UNKNOWN;
	}

	/* Retry = 0 - do not retry, 1 - with changing passcodes */
	int tries;
	for (tries = 0; tries < (retry == 0 ? 1 : 3); tries++) {
		if (tries == 0 || retry == 1) {
			/* First time or we are retrying while changing the password */
			retval = pam_handle_load(pamh, flags, enforced, &s);
			if (retval != 0)
				goto cleanup;

			/* Generate prompt */
			ppp_calculate(&s);
			prompt = ppp_get_prompt(&s);
			if (!prompt) {
				print(PRINT_ERROR, "Error while generating prompt\n");
				retval = PAM_AUTH_ERR;
				goto cleanup;
			}
		}

		resp = pam_query_user(pamh, flags, show, prompt, &s);

		retval = PAM_AUTH_ERR; 
		if (!resp) {
			/* No response? */
			goto cleanup;
		}

		if (ppp_authenticate(&s, resp[0].resp) == 0) {
			_pam_drop_reply(resp, 1);
			
			/* Correctly authenticated */
			retval = PAM_SUCCESS;
			goto cleanup;
		}

		/* Error during authentication */
		print(PRINT_NOTICE, "secure %d retry %d flags %d\n", secure, retry, s.flags);
		if (retry == 0 && secure == 0 && !(s.flags & FLAG_SKIP)) {
			/* Decrement counter */
			retval = ppp_load_decrement(&s);
			if (retval != 0) {
				retval = PAM_AUTH_ERR;
				print(PRINT_WARN, "Error while decrementing\n");
				goto cleanup;
			}
		}

		retval = PAM_AUTH_ERR;
	}

cleanup:
	state_fini(&s);
	print_fini();
	return retval;
}

PAM_EXTERN int pam_sm_open_session(
	pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval = PAM_IGNORE;
	return retval;
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
