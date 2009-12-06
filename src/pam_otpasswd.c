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

/* getpwnam */
#include <sys/types.h>
#include <pwd.h>

/* stat() */
#include <sys/stat.h>
#include <unistd.h>

/* waitpid() */
#include <sys/wait.h>

/* kill() */
#include <signal.h>

#include "print.h"
#include "ppp.h"

/* Username used to drop root */
#define SECURE_USERNAME "nobody"

enum {
	OOB_DISABLED = 0,
	OOB_REQUEST = 1,
	OOB_SECURE_REQUEST = 2,
	OOB_ALWAYS = 3
};

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

	/* Out-Of-Band script path */
	/* Ensure that size of this field matches sscanf in _parse_options */
	char oob_path[200];

	/* 0 - OOB disabled
	 * 1 - OOB on request
	 * 2 - OOB on request; request requires password
	 * 3 - OOB sent during all authentication sessions
	 */
	int oob;

	/* Parameters determined from the environment and
	 * not options themselves  */
	int uid, gid; /* uid, gid of a safe, non-root user who can run OOB script */
} options;

static int _parse_options(options *opt, int argc, const char **argv)
{
	struct passwd *pwd;

	/* Default values */
	opt->retry = opt->enforced = opt->secure = opt->debug = 0;
	opt->show = 1;
	opt->oob = 0;
	opt->oob_path[0] = '\0';

	/* Look for a user we can use to drop root.
	 * This can either be 'otpasswd' user or 'nobody'
	 * in /etc/passwd */
	pwd = getpwnam(SECURE_USERNAME);
	if (pwd == NULL) {
		print(PRINT_ERROR,
		      "otpasswd requires user "SECURE_USERNAME
		      " to exists.\n");
		goto error;
	}
	opt->uid = pwd->pw_uid;
	opt->gid = pwd->pw_gid;

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
				goto error;
			}
		} else if (sscanf(*argv, "oob=%d", &opt->oob) == 1) {
			if (opt->oob < 0 || opt->oob > 3) {
				print(PRINT_ERROR, "Invalid OOB parameter (valid values = 0, 1, 2, 3)");
				goto error;
			}
		} else if (sscanf(*argv, "oob_path=%199s", opt->oob_path) == 1) {
			/* Ensure path is correct */
			struct stat st;
			if (stat(opt->oob_path, &st) != 0) {
				print(PRINT_ERROR, "Unable to access oob sender. Check oob_path parameter\n");
				goto error;
			}

			if (!S_ISREG(st.st_mode)) {
				print(PRINT_ERROR, "oob_path is not a file!\n");
				goto error;
			}

			/* Check permissions */
			if (st.st_mode & S_IXOTH) {
				print(PRINT_WARN, "Others can execute OOB utility\n");
			} else {
				/* That's cool, but can we execute it? */
				const int can_owner = ((st.st_mode & S_IXUSR) && st.st_uid == opt->uid);
				const int can_group = ((st.st_mode & S_IXGRP) && st.st_gid == opt->gid);
				if (! (can_owner || can_group) ) {
					/* Neither from group nor from owner mode */
					/* TODO: testcase this */
						print(PRINT_ERROR,
						      SECURE_USERNAME " is unable to execute OOB utility!\n");
						goto error;
				}
			}

		} else {
			print(PRINT_ERROR, "Invalid parameter %s\n", *argv);
			goto error;
		}
	}
	return 0;

error:
	print(PRINT_ERROR, "Error while parsing parameters\n");
	return PAM_AUTH_ERR;
}

/* Send out of band message by calling external script 
 * state parameter is generally const, but child will 
 * clean it up */
static int _out_of_band(const options *opt, state *s)
{
	int retval;
	char current_passcode[17];
	char contact[STATE_CONTACT_SIZE];

	/* Check if OOB enabled */
	if (!opt->oob_path || opt->oob == 0) {
		print(PRINT_WARN, "Trying OOB when it's not enabled\n");
		return 1;
	}

	/* Gather required data */
	retval = ppp_get_current(s, current_passcode);
	if (retval != 0)
		return retval;

	const char *c = ppp_get_contact(s);
	if (!c || strlen(c) == 0) {
		print(PRINT_WARN, "User without contact data required OOB transmission\n");
		return 2;
	}
	/* Copy, as releasing state will remove this data from RAM */
	strncpy(contact, c, sizeof(contact)-1);

	pid_t new_pid;
	new_pid = fork();
	if (new_pid == -1) {
		print(PRINT_ERROR, "Unable to fork and call OOB utility\n");
		return 1;
	}

	if (new_pid == 0) {
		// dangerous print, remove it 
		print(PRINT_NOTICE, "Executing OOB transmission of %s to %s\n", 
		      current_passcode, contact);

		/* We don't want to leave state in memory! */
		/* TODO/FIXME: What with the locks? */
		retval = ppp_release(s, 0, 0);
		if (retval != 0) {
			print(PRINT_ERROR, "RELEASE FAILED IN CHILD!");
			exit(10);
		}

		/* Drop root */
		retval = setgid(opt->gid);
		if (retval != 0) {
			print_perror(PRINT_ERROR, "UNABLE TO CHANGE GID TO %d\n", opt->gid);
			exit(11);
		}

		retval = setuid(opt->uid);
		if (retval != 0) {
			print_perror(PRINT_ERROR, "UNABLE TO CHANGE UID TO %d\n", opt->uid);
			exit(12);
		}

		execl(opt->oob_path, opt->oob_path, contact, current_passcode, NULL);

		/* Whoops */
		print_perror(PRINT_ERROR, "OOB utility execve failed! Program error; "
			     "this should be detected beforehand");
		exit(13);
	}

	/*** Parent ***/
	/* Wait a bit for your child to finish.
	 * If it decides to hang up cheerfully kill it.
	 * Then clean up the bod^C^C garbage.
	 */
	int times;
	int status = 0;
	for (times = 200; times > 0; times--) {
		usleep(7000);
		retval = waitpid(new_pid, &status, WNOHANG);
		if (retval == new_pid)
			break; /* Our child finished */
		if (retval == -1) {
			print_perror(PRINT_ERROR, "waitpid failed");
			return 1;
		}
		if (retval == 0) {
			print(PRINT_NOTICE,  "Waiting for  OOB return\n");
			continue;
		}
	}

	if (times == 0) {
		/* Timed out while waiting for it's merry death */
		(void) kill(new_pid, 9);

		/* waitpid should return immediately now, but just wait to be sure */
		usleep(100);
		(void) waitpid(new_pid, NULL, WNOHANG);
		print(PRINT_ERROR, "Timed out while waiting for OOB utility to die. Fix it!\n");
		return 2;
	}

	print(PRINT_NOTICE, "OOB child returned fast\n");

	if (WEXITSTATUS(status) == 0)
		print(PRINT_NOTICE, "OOB utility successful\n");
	else {
		print(PRINT_WARN, "OOB utility returned %d\n", WEXITSTATUS(status));
	}

	return 0;
}


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

static struct pam_response *_query_user(pam_handle_t *pamh, int flags, int show, const char *prompt, const state *s)
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

	/* Close bootstrapped logging */
	print_fini();

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

		/* If user configurated OOB to be send
		 * all the time - sent it */
		if (opt.oob == OOB_ALWAYS) {
			_out_of_band(&opt, s);
		}

		resp = _query_user(pamh, flags, opt.show, prompt, s);

		retval = PAM_AUTH_ERR;
		if (!resp) {
			/* No response? */
			print(PRINT_NOTICE, "No response from user during auth.\n");
			goto cleanup;
		}

		/* Hook up OOB request */
		if (strlen(resp[0].resp) == 1 && resp[0].resp[0] == '.') {
			switch (opt.oob) {
			case OOB_REQUEST:
				_out_of_band(&opt, s);
				/* Restate question about passcode */
				_pam_drop_reply(resp, 1);
				resp = _query_user(pamh, flags, opt.show, prompt, s);				
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
			print(PRINT_NOTICE, "Authentication succeded\n");
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

	print(PRINT_NOTICE, "Authentication failed\n");

cleanup:
	ppp_fini(s);
	print(PRINT_NOTICE, "otpasswd finished\n");
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
	retval = _init(pamh, argc, argv, &opt, &s);
	if (retval != 0)
		return retval;

	print(PRINT_NOTICE, "(session) entrance\n");

	if (ppp_load(s) != 0)
		goto exit;

	print(PRINT_NOTICE, "(session) state loaded\n");

	int err = ppp_get_warning_condition(s);
	if (err == 0) {
		/* No warnings! */
		print(PRINT_NOTICE, "(session) no warning to be printed\n");
		goto cleanup;
	}

	const char *msg = ppp_get_warning_message(err);

	if (!msg) {
		/* Should never happen */
		print(PRINT_NOTICE, "(session) no warning returned\n");
		goto cleanup;
	}

	/* Generate message */
	char buff_msg[200], buff_ast[200];
	int len, i;

	len = snprintf(buff_msg, sizeof(buff_msg), "* WARNING: %s *", msg);
	if (len < 10) {
		print(PRINT_ERROR, "(session) sprintf error\n");
		goto cleanup;
	}

	for (i=0; i<len && i < sizeof(buff_ast)-1; i++)
		buff_ast[i] = '*';
	buff_ast[i] = '\0';
	/* FIXME: musn't we use single _show_message? */
	_show_message(pamh, flags, buff_ast);
	_show_message(pamh, flags, buff_msg);
	_show_message(pamh, flags, buff_ast);

cleanup:
	ppp_release(s, 0, 1); /* Unlock, do not store */
exit:
	ppp_fini(s);

	print(PRINT_NOTICE, "otpasswd finished\n");
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
