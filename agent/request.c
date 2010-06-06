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

#include "agent_private.h"
#include "security.h"

/***
 * Private helper functions
 ***/

/** Used to communicate how previous request was finished
 * without returning any important data (but the data might
 * be set before this command to sent it along)
 */
static int _send_reply(agent *a, int status) 
{
	agent_hdr_set_status(a, status);
	agent_hdr_set_type(a, AGENT_REQ_REPLY);
	int ret = agent_hdr_send(a);
	print(PRINT_NOTICE, "Reply sent (%d)\n", ret);
	return ret;
}

/* Initialize state; possibly by loading from file  */
static int _state_init(agent *a, int load, int lock)
{
	int ret;

	assert(a);
	assert(a->s == NULL);
	a->new_state = 0;

	ret = ppp_state_init(&a->s, a->username);
	if (ret != 0) {
		return ret;
	}

	if (load == 0) {
		/* Just initialize */
		return 0;
	}

	if (lock)
		ret = ppp_state_load(a->s, 0);
	else
		ret = ppp_state_load(a->s, PPP_DONT_LOCK);

	if (ret != 0) {
		ppp_state_fini(a->s);
		a->s = NULL;
	}

	print(PRINT_NOTICE, "State initialization done (%d)\n", ret);
	return ret;
}

/* Store if necessary, unlock and clean&free memory */
static int _state_fini(agent *a, int store, int remove)
{
	int ret;
	assert(!(store && remove)); /* Not at once */
	assert(a->s);

	if (!a->s) {
		return AGENT_ERR_NO_STATE;
	}

	/* We store changes into the file
	 * We don't need to unlock just yet - ppp_fini
	 * will unlock state if it was locked
	 */
	int flags = 0;
	if (remove)
		flags = PPP_REMOVE;
	else if (store)
		flags = PPP_STORE;

	ret = ppp_state_release(a->s, flags);

	if (ret != 0) {
		print(PRINT_ERROR, 
		      "Error while saving state data. State not changed. [%d]\n", ret);
	}

	ppp_state_fini(a->s);

	a->s = NULL;

	print(PRINT_NOTICE, "State finalization done (%d)\n", ret);
	return ret;
}





static int request_verify_policy(const agent *a, const cfg_t *cfg)
{
	/* Read request parameters */
	const int r_type = agent_hdr_get_type(a);
/*
	const int r_status = agent_hdr_get_status(a);
	const int r_int = agent_hdr_get_arg_int(a);
	const num_t r_num = agent_hdr_get_arg_num(a);
	const char *r_str = agent_hdr_get_arg_str(a);
*/
	/* FIXME: Write this function 
	 * Most of it's functionality will be accomplished
	 * at PPP level.
	 */
	return AGENT_OK;

	switch (r_type) {
	case AGENT_REQ_USER_SET:
		/* Only administrator can select username */
		if (security_is_privileged())
			return AGENT_OK;
		else
			return AGENT_ERR_POLICY;

	case AGENT_REQ_DISCONNECT:
		return AGENT_REQ_DISCONNECT;


	case AGENT_REQ_STATE_NEW:
	case AGENT_REQ_STATE_LOAD:
	case AGENT_REQ_STATE_STORE:
	case AGENT_REQ_KEY_GENERATE:
	case AGENT_REQ_KEY_REMOVE:
		return AGENT_OK;


		/* FLAGS */
	case AGENT_REQ_FLAG_SET:
		break;

	case AGENT_REQ_FLAG_CLEAR:
		break;

	case AGENT_REQ_FLAG_CHECK:
		break;

	case AGENT_REQ_FLAG_GET:
		break;
			
	default:
		print(PRINT_ERROR, "Unrecognized request type.\n");
		return AGENT_ERR;
	}

	return AGENT_ERR_POLICY;
}

static int request_execute(agent *a, const cfg_t *cfg)
{
	int ret;
	const int privileged = security_is_privileged();
	const int ppp_flags = privileged ? 0 : PPP_CHECK_POLICY;

	/* Read request parameters */
	const int r_type = agent_hdr_get_type(a);
//	const int r_status = agent_hdr_get_status(a);
//	const int r_int = agent_hdr_get_arg_int(a);
//	const num_t r_num = agent_hdr_get_arg_num(a);
	const char *r_str = agent_hdr_get_arg_str(a);

	print(PRINT_NOTICE, "Executing request %d\n", r_type);
	switch (r_type) {
	case AGENT_REQ_DISCONNECT:
		/* Correct disconnect */
		/* Clear data */
		if (a->s) {
			ret = _state_fini(a, 0, 0);
			if (ret != 0) {
				print(PRINT_WARN, 
				      "Error while handling finalizing "
				      "state during disconnect: %s\n",
				      agent_strerror(ret));
			}
		}
		return AGENT_REQ_DISCONNECT;

	case AGENT_REQ_USER_SET:
	{
		if (!r_str) {
			_send_reply(a, AGENT_ERR_REQ);
			break;
		}

		char *username = security_parse_user(r_str);
		if (!username) {
			_send_reply(a, AGENT_ERR_REQ_ARG);
			break;
		}

		agent_set_user(a, username);
		username = NULL;

		/* Clear state */
		if (a->s) {
			_state_fini(a, 0, 0);
			a->s = NULL;
		}
		
		_send_reply(a, AGENT_OK);
		break;
	}

		/* STATE */
	case AGENT_REQ_STATE_NEW:
		if (a->s)
			return AGENT_ERR;

		ret = _state_init(a, 0, 0);
		if (ret != 0) {
			print(PRINT_WARN, "Error while handling STATE_NEW: %s\n",
			      agent_strerror(ret));
			return ret;
		}
		a->new_state = 1;
		_send_reply(a, ret);
		break;


	case AGENT_REQ_STATE_LOAD:
		if (a->s)
			return AGENT_ERR;

		/* Load without locking; we won't be able to save */
		ret = _state_init(a, 1, 0);
		if (ret != 0) {
			print(PRINT_WARN, "Error while handling STATE_LOAD: %s\n",
			      agent_strerror(ret));
		} 
		a->new_state = 0;
		_send_reply(a, ret);
		break;

	case AGENT_REQ_STATE_STORE:
		ret = _state_fini(a, 1, 0);
		if (ret != 0) {
			print(PRINT_WARN, "Error while handling STATE_STORE: %s\n",
			      agent_strerror(ret));
		}
		_send_reply(a, ret);
		break;

	case AGENT_REQ_STATE_DROP:
		if (a->s) {
			ret = _state_fini(a, 0, 0);
		} else {
			/* Nothing to drop */
			print(PRINT_WARN, "Unable to drop non-existant state\n");
			ret = AGENT_ERR_NO_STATE;
		}
		_send_reply(a, ret);
		break;


		/* KEY */
	case AGENT_REQ_KEY_GENERATE:
		print(PRINT_NOTICE, "Request: KEY_GENERATE\n");

		if (!a->s) {
			print(PRINT_ERROR, "Must create new state first\n");
			_send_reply(a, AGENT_ERR_MUST_CREATE_STATE);
			break;
		}

		ret = ppp_key_generate(a->s, ppp_flags);
		
		if (ret != 0) {
			print(PRINT_ERROR, "Error while creating new key\n");
		} else {
			ret = AGENT_OK;
		}

		_send_reply(a, ret);
		break;

	case AGENT_REQ_KEY_REMOVE:
		if (a->s) {
			ret = _state_fini(a, 0, 1);
			if (ret != 0) {
				print(PRINT_ERROR, "Error while removing user state\n");
			}
		} else {
			print(PRINT_ERROR,
			      "State must be loaded before trying to remove it from system.\n");
			ret = AGENT_ERR;
		}
		
		_send_reply(a, ret);
		break;

		/* FLAGS */
	case AGENT_REQ_FLAG_SET:
		print(PRINT_NOTICE, "Request: FLAG_SET\n");
		_send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_CLEAR:
		print(PRINT_NOTICE, "Request: FLAG_CLEAR\n");
		_send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_CHECK:
		print(PRINT_NOTICE, "Request: FLAG_CHECK\n");
		_send_reply(a, AGENT_ERR);
		break;

	case AGENT_REQ_FLAG_GET:
		print(PRINT_NOTICE, "Request: FLAG_GET\n");
		_send_reply(a, AGENT_ERR);
		break;
			
			
	default:
		print(PRINT_ERROR, "Unrecognized request type.\n");
		return 1;
	}

	return AGENT_OK;
}


/***
 * Public interface used by agent.c
 ***/
int request_handle(agent *a) 
{
	int ret;

	cfg_t *cfg = cfg_get();
	assert(cfg);

	/* Wait for request, perform it and reply */
	ret = agent_hdr_recv(a);
	if (ret != 0) {
		print(PRINT_ERROR, "Client disconnected while waiting for request header (%d).\n", ret);
		return 1;
	}
		
	/* Read request parameters */
	const int r_type = agent_hdr_get_type(a);
//	const int r_status = agent_hdr_get_status(a);
//	const int r_int = agent_hdr_get_arg_int(a);
//	const num_t r_num = agent_hdr_get_arg_num(a);
//	const char *r_str = agent_hdr_get_arg_str(a);

	print(PRINT_NOTICE, "Received request header of type %d\n", r_type);

	ret = request_verify_policy(a, cfg);
	if (ret != 0) {
		_send_reply(a, AGENT_ERR_POLICY);
		return ret;
	}

	/* This will send request reply itself */
	ret = request_execute(a, cfg);

	return ret;
}
