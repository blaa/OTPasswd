/*
 * Testcase on live PAM.
 * To perform it you must:
 * 1) Have otpasswd instlled in system.
 * 2) example/otpasswd-testcase placed in /etc/pam.d
 * 3) User with created state file.
 * 3a) You can also check how will it work when state is inconsistent,
 *     errornous or missing.
 * 4) Run it like this (you can run it not on root! but on a user
 *    which can access state file)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>


int conversation(int num_msg, const struct pam_message **msg, 
		 struct pam_response **resp, void *appdata_ptr)
{
	if (num_msg != 1) {
		printf("Num_msg should always be one in this test!\n");
		return 1;
	}

	printf("Conversation:\n");
	switch (msg[0]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
		printf("\tprompt echo: ");
		break;
	case PAM_PROMPT_ECHO_OFF:
		printf("\tprompt noecho: ");
		break;
		
	case PAM_ERROR_MSG:
		printf("\terror msg: ");
		break;
		
	case PAM_TEXT_INFO:
		printf("\ttext info: ");
		break;
		
	}
	printf("%s\n", msg[0]->msg);

	if (msg[0]->msg_style == PAM_PROMPT_ECHO_ON ||
	    msg[0]->msg_style == PAM_PROMPT_ECHO_OFF) {
		    const char *reply = (const char *)appdata_ptr;

		    struct pam_response *r;

		    if (*resp) {
			    printf("**** STRANGE ****\n");
		    }
		    r = *resp = malloc(sizeof(*r));
		    if (!r)
			    return 1;

		    printf("\tResponding with: %s\n", reply);

		    /* Store reply */
		    r->resp = strdup(reply);
		    r->resp_retcode = 0;
		    
	    }
	printf("\tConversation finished\n");
	return 0;
}


int authenticate(const char *user, char *answer)
{
	struct pam_conv pc;
	int ret, retval;
	pam_handle_t *pamh = NULL;

	/* Set conversation func */
	pc.conv = conversation;
	pc.appdata_ptr = answer;

	ret = pam_start("otpasswd-testcase", user, &pc, &pamh);

	if (ret != PAM_SUCCESS) {
		printf("pam_start returned %d\n", ret);
		return 1;
	}

	ret = pam_authenticate(pamh, 0);

	printf("Authentication returned %d, that is ", ret);
	switch (ret) {
	case PAM_ABORT:
		printf("abort\n");
		retval = 1;
		break;

	case PAM_AUTH_ERR:
		printf("err\n");
		retval = 2;
		break;

	case PAM_CRED_INSUFFICIENT:
		printf("cred insuf\n");
		retval = 3;
		break;

	case PAM_AUTHINFO_UNAVAIL:
		printf("authinfo unvail\n");
		retval = 4;
		break;

	case PAM_MAXTRIES:
		printf("maxtries\n");
		retval = 5;
		break;

	case PAM_SUCCESS:
		printf("success\n");
		retval = 6;
		break;

	case PAM_USER_UNKNOWN:
		printf("user unknown\n");
		retval = 7;
		break;

	case PAM_AUTHTOK_RECOVERY_ERR:
		printf("Unable to reach for password. Run this testcase as root\n");
		retval = 20;
		break;

	default:
		printf("(not recognized. See _pam_types.h)\n");
		retval = 9;
		break;
	}

	/* If success, try session */
	if (retval == 6) {
		printf("Session test...\n");
		if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
			printf("Open session failed\n");
			retval += 100;
		} else if (pam_close_session(pamh, 0) != PAM_SUCCESS) {
			printf("Close session failed!\n");
			retval += 1000;
		} else {
			printf("Session test OK\n");
		}
	}


	pam_end(pamh, ret);

	return retval;
}

int main(int argc, char **argv)
{
	int ret, retval;
	
	if (argc < 3) {
		printf("Usage: %s <user for auth> <correct code>\n", argv[0]);
		return 1;
	}

	ret = 0;

	/* Correct authentication */
	retval = authenticate(argv[1], argv[2]);
	if (retval != 0) {
		printf("*** Correct auth testcase failed (%d)\n", retval);
		ret++;
	}

	/* Failed authenticate */
	retval = authenticate(argv[1], "failedfailedfailed");
	if (retval == 0) {
		printf("*** Failed auth testcase failed (%d)\n", retval);
		ret++;
	}

	return ret;
}
