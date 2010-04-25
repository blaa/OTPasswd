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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <assert.h>

/* agent communication */
#include "agent_private.h"

/* libotp header */
#include "ppp.h"

/* Utility headers */
#include "security.h"
#include "actions.h"
#include "testcases.h"


/* Testcase function should be run only if we're not 
 * a SUID program or when we are run by root.
 * Also we should be connected to the terminal and
 * not to a pipe
 */
int do_testcase(void)
{
	cfg_t *cfg;
	int retval;
	int tmp;
	int failed = 0;

	printf("*** Running testcases\n");

	/* Init ppp for testcases */
	retval = ppp_init(PRINT_STDOUT, NULL);
	if (retval != 0) {
		puts(ppp_get_error_desc(retval));
		printf("Testcasing failed:\n");
		printf("OTPasswd not correctly installed.\n");
		printf("Consult installation manual for detailed information.\n");
		ppp_fini();
		return 1;
	}
			
	/* Will succeed, as ppp_init suceeded */
	cfg = cfg_get();
	if (!cfg) {
		printf("FATAL: Unable to read config file.\n");
		return 1;
	}




	/* Change DB info so we won't overwrite anything
	 * important */
	strcpy(cfg->user_db_path, ".otpasswd_testcase");
	strcpy(cfg->global_db_path, "/tmp/otshadow_testcase");
	cfg->db = CONFIG_DB_USER;

	tmp = num_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d num testcases failed\n******\n", tmp);

	tmp = config_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d config testcases failed\n******\n", tmp);

	tmp = state_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d state testcases failed\n******\n", tmp);

	tmp = crypto_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d crypto testcases failed\n******\n", tmp);

	tmp = card_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d card testcases failed\n******\n", tmp);

	tmp = ppp_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d ppp testcases failed\n******\n", tmp);


	if (failed) {
		printf(("***********************************************\n"
		        "*         !!! %d testcases failed !!!         *\n"
		        "* Don't use this release until this is fixed! *\n"
		        "* Note: Testcases should be run with default  *\n"
		        "* conpilation options and config.             *\n"
		        "* If unsure, reinstall and rerun --check      *\n"
		        "***********************************************\n"),
		       failed);
		retval = 1;
	} else {
		printf(("**********************************\n"
		        "* All testcases seem successful. *\n"
		        "**********************************\n"));
		retval = 0;
	}

	ppp_fini();
	return retval;
}


int perform_action(int argc, char **argv, options_t *options, cfg_t *cfg)
{
	int retval;

	/* Reconfigure printing subsystem; -v might be passed */
	switch (cfg->pam_logging) {
	case 0: print_config(PRINT_STDOUT | PRINT_NONE); break;
	case 1: print_config(PRINT_STDOUT | PRINT_ERROR); break;
	case 2: print_config(PRINT_STDOUT | PRINT_WARN); break; 
	case 3: print_config(PRINT_STDOUT | PRINT_NOTICE); break; 
	default:
		assert(0);
		retval = 1;
		goto cleanup;
	}

	/* Perform action */
	switch (options->action) {
	case 0:
		printf(("No action specified. Try passing -k, -s, -t or -l\n\n"));
		retval = 1;
		goto cleanup;
/*
	case OPTION_KEY:
	case OPTION_REMOVE:
		retval = action_key(options);
		break;

	case OPTION_SPASS:
		retval = action_spass(options);
		break;

	case OPTION_ALPHABETS:
	case OPTION_CONFIG:
	case OPTION_INFO:
	case OPTION_INFO_KEY:
		retval = action_flags(options);
		break;

	case OPTION_AUTH:
		ret = action_authenticate(options);
		if (ret == 0)
			retval = 1;
		else
			retval = 0;
		break;
	case OPTION_VERSION:
		retval = action_license(options);
		break;

	case OPTION_WARN:
	case OPTION_SKIP:
	case OPTION_TEXT:
	case OPTION_LATEX:
	case OPTION_PROMPT:
		retval = action_print(options);
		break;
*/
	default:
		printf(("Program error. You shouldn't end up here.\n"));
		assert(0);
		retval = 1;
		goto cleanup;
	}


cleanup:
	free(options->action_arg);
	free(options->label);
	free(options->contact);
	free(options->username);
	ppp_fini();
	return retval;
}

/** Used to communicate how previous request was finished
 * without returning any important data (but the data might
 * be set before this command to sent it along)
 */
int send_reply(agent *a, int status) 
{
	agent_hdr_set_status(a, status);
	agent_hdr_set_type(a, AGENT_REQ_REPLY);
	return agent_hdr_send(a);
}

/** Marks end of initialization (succeeded or not) */
int send_init_reply(agent *a, int status) 
{
	agent_hdr_set_status(a, status);
	agent_hdr_set_type(a, AGENT_REQ_INIT);
	return agent_hdr_send(a);
}



int do_handle_request(agent *a) 
{
	int ret;

	/* Wait for request, perform it and reply */
	ret = agent_hdr_recv(a);
	if (ret != 0) {
		print(PRINT_ERROR, "Client disconnected\n");
		return 1;
	}
		
	/* Read request parameters */
	const int r_type = agent_hdr_get_type(a);
	const int r_status = agent_hdr_get_status(a);
	const int r_int = agent_hdr_get_arg_int(a);
	const num_t r_num = agent_hdr_get_arg_num(a);
	const char *r_str = agent_hdr_get_arg_str(a);

	switch (r_type) {
	case AGENT_REQ_DISCONNECT:
		/* Correct close */
		return 0;

		/* KEY */
	case AGENT_REQ_KEY_GENERATE:
		print(PRINT_NOTICE, "Request: KEY_GENERATE\n");
		send_reply(a, AGENT_ERR);
		break;
	case AGENT_REQ_KEY_REMOVE:
		print(PRINT_NOTICE, "Request: KEY_REMOVE\n");
		send_reply(a, AGENT_ERR);
		break;
	case AGENT_REQ_KEY_STORE:
		print(PRINT_NOTICE, "Request: KEY_STORE\n");
		send_reply(a, AGENT_ERR);
		break;

		/* STATE */
	case AGENT_REQ_READ_STATE:
		print(PRINT_NOTICE, "Request: READ_STATE\n");
		send_reply(a, AGENT_ERR);
		break;

		/* FLAGS */
	case AGENT_REQ_FLAG_SET:
		print(PRINT_NOTICE, "Request: FLAG_SET\n");
		send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_CLEAR:
		print(PRINT_NOTICE, "Request: FLAG_CLEAR\n");
		send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_CHECK:
		print(PRINT_NOTICE, "Request: FLAG_CHECK\n");
		send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_GET:
		print(PRINT_NOTICE, "Request: FLAG_GET\n");
		send_reply(a, AGENT_ERR);
		break;
			
			
	default:
		print(PRINT_ERROR, "Unrecognized request type.\n");
		return 1;
	}

	return 0;
}


int do_loop(void) 
{
	int ret;

	/* Everything seems fine; send message that we're ready */
	agent *a;
	ret = agent_server(&a);
	if (ret != AGENT_OK) {
		print(PRINT_ERROR, "Unable to start agent server\n");
		return 1;
	}

	ret = agent_hdr_set(a, 0, 0, NULL, NULL);
	assert(ret == 0);

	ret = send_init_reply(a, AGENT_REQ_INIT);
	if (ret != 0) {
		print(PRINT_ERROR, "Initial reply error; agent_query returned %d\n", ret);
		goto end;
	}

	for (;;) {
		ret = do_handle_request(a);
		if (ret != 0)
			goto end;
	}

end:
	ppp_fini();
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	cfg_t *cfg = NULL;

	/* 1) Init safe environment, store current uids, etc. */
	security_init();

	if (!security_is_tty_detached()) {
		/* We have stdout */
		/* Check if we should run testcases. */
		if (argc == 2 && strcmp(argv[1], "--check") == 0) {
			if (!security_is_suid() || security_is_privileged()) {
				/* We're not suid or we are root already */
				return do_testcase();
			}
		}

		printf("FATAL: This program should not be used like this.\n"
		       "Use appropriate interface instead (like otpasswd).\n\n");


		if (!security_is_suid()) {
			printf("Since this program is not SUID you can run\n"
			       "a set of testcases with --check option.\n");
		} else {
			if (security_is_privileged()) {
				printf("Since you're running this program as root you can\n"
				       "run a set of testcases with --check option\n");
			}
		}
		exit(EXIT_FAILURE);
	}


	/* After this point we:
	 * a) Have no controlling terminal. 
	 * b) Can be SUID root (run by root or normal user)
	 */


	/***
	 * Initialization
	 * Now, try to read config file, init printing, ppp etc.
	 ***/

	/* TODO/FIXME: Reply our caller frame with error description on initial failure 
	 */

	/* TODO, FIXME: Remove log from here! */
	ret = ppp_init(0, "/tmp/OTPAGENT_TESTLOG");
	if (ret != 0) {
		print(PRINT_ERROR, ppp_get_error_desc(ret));
		print(PRINT_ERROR, "OTPasswd not correctly installed.\n");
		print(PRINT_ERROR, "Consult installation manual for detailed information.\n");
		ppp_fini();
		return 1;
	}

	/* Will succeed, as ppp_init suceeded */
	cfg = cfg_get();

	/* If DB is global, mysql or ldap, utility must be SUID root. 
	 * We can't detect this easily if we are run by root. So, 
	 * treat root as run by suid.
	 */
	if (cfg->db != CONFIG_DB_USER &&
	    security_is_suid() == 0 && 
	    security_is_privileged() == 0) {
		/* Something is wrong. We are not SUID/privileged
		 * and DB is not "USER" so we won't be able to reach it */
		print(PRINT_ERROR,
		      "Database type set to global, MySQL or LDAP, yet program "
		      "is not a SUID root.\n");
		ppp_fini();
		return 1;
	}


	/* 4) We must drop permissions now.
	 * If DB=user - drop to the user who called us.
	 * If DB=global - drop to cfg->user_uid
	 */
	switch (cfg->db) {
	case CONFIG_DB_GLOBAL:
		/* Drop root permanently to the cfg->user_uid 
		 * We do this even if we are run as root. */
		security_permanent_switch(cfg->user_uid, cfg->user_gid);
		break;
		
	case CONFIG_DB_MYSQL:
	case CONFIG_DB_LDAP:
	case CONFIG_DB_USER:
		/* Drop permanently back to the user who called us */
		/* FIXME: User won't be able to ptrace us 
		   rather and get passwords... */
		if (!security_is_privileged()) {
			/* We don't drop if we are root, so the --user
			 * option will work. */
			security_permanent_drop();
		}
		break;
	}

	/* Agent loop */
	return do_loop();
}
