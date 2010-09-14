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
 *
 * DESC: 
 * Interface between SUID agent and UI program. Can and should be used
 * for creation of GUI interfaces also.
 **********************************************************************/

#ifndef _AGENT_INTERFACE_H_
#define _AGENT_INTERFACE_H_

#include "num.h"

#ifndef AGENT_INTERNAL
/* If internal representation is not defined,
 * define it as anonymous struct */
typedef struct agent agent;
#endif

/* Error description of PPP internals */
#include "ppp_common.h"

/** Error description structure. 
 * Musn't collide with PPP errors from ppp_common.h 
 */
enum AGENT_ERROR {
	/*** Generic ***/
	AGENT_OK=0,
	AGENT_ERR=5000,

	/* Incorrect request */
	AGENT_ERR_REQ, 
	/* Incorrect request argument */
	AGENT_ERR_REQ_ARG,
	
	/*** Initial errors ***/
	AGENT_ERR_INIT_CONFIGURATION,
	AGENT_ERR_INIT_PRIVILEGES,
	AGENT_ERR_INIT_USER,
	AGENT_ERR_INIT_EMERGENCY,
	AGENT_ERR_INIT_EXECUTABLE,

	/*** Various errors ***/
	AGENT_ERR_MEMORY,
	AGENT_ERR_SERVER_INIT,
	AGENT_ERR_PROTOCOL_MISMATCH,
	AGENT_ERR_DISCONNECT,

	/* Policy errors, generic and with hints */
	AGENT_ERR_POLICY,
	AGENT_ERR_POLICY_REGENERATION,
	AGENT_ERR_POLICY_GENERATION,
	AGENT_ERR_POLICY_DISABLED,
	AGENT_ERR_POLICY_SALT,
	AGENT_ERR_POLICY_SHOW,

	/*** Coding/assumptions errors ***/
	AGENT_ERR_MUST_CREATE_STATE,
	AGENT_ERR_MUST_DROP_STATE,
	AGENT_ERR_NO_STATE,
};

/** Check if given number is an STATE/PPP/AGENT error
 * Other options include a random error (numbers < 10)
 * or a multi-valued bit-field returned from PPP 
 */
static inline int agent_is_agent_error(int error) 
{
	if (error >= 5000 && error < 5100)
		return 1;
	if (error >= 1000 && error < 1100)
		return 2; /* State error */
	if (error >= 3000 && error < 3100)
		return 2; /* PPP error */

	return 0;
}

/*** Basic routines ***/

/** Connect to agent through the given executable.
 *
 * @param agent_executable can be NULL, defaults will be checked
 */
extern int agent_connect(agent **a_out, const char *agent_executable);

/** Disconnect from agent, kill connection */
extern int agent_disconnect(agent *a);

/** Set the username of user whose state we want to mangle */
extern int agent_set_user(agent *a, const char *username);

/** Return translated description of last error */
extern const char *agent_strerror(int error);

/** Display all static password related errors. 
 * TODO: Make this return one-by-one and clear bits */
extern void agent_print_spass_errors(int errors);

/** Display all warnings related to state */
extern void agent_print_ppp_warnings(int warnings, int failures);

/*** Actions ***/

/** Creates new state - done before generating key. */
extern int agent_state_new(agent *a);

/** Loads users state information. */
extern int agent_state_load(agent *a);

/** Drops loaded or new state */
extern int agent_state_drop(agent *a);

/** Stores previously generated and configured key. */
extern int agent_state_store(agent *a);


/** Generate new key, but do not store it on disc. 
 * Flags can be set with different command separately. */
extern int agent_key_generate(agent *a);


/** Remove user state; warnings about otp enforcements are due to UI */
extern int agent_key_remove(agent *a);


/*** Flag interface ***/
/** Set certain flags (oring with current) */
extern int agent_flag_add(agent *a, int flag);

/** Clear some flag (negate and AND with current) */
extern int agent_flag_clear(agent *a, int flag);

/** Read set of state flags */
extern int agent_flag_get(agent *a, int *flags);


/*** Status query ***/
/** Get NUM variable from state (max_code, etc.) */
extern int agent_get_num(agent *a, int field, num_t *key);
/** Get integer variable from state (failured, etc.) */
extern int agent_get_int(agent *a, int field, int *integer);

/* Getters returning string data allocates it; you 
 * have to free it yourself */
extern int agent_get_str(agent *a, int field, char **str);

/** Read key from state (binary data)
 *
 * @param key must have prepared place for 32 bytes.
 */
extern int agent_get_key(agent *a, unsigned char *key);

/*** Setters ***/
/** Set integer inside the state */
extern int agent_set_int(agent *a, int field, int integer);

/** Set string in state (label/contact) */
extern int agent_set_str(agent *a, int field, const char *str);

/** Set static password in the state */
extern int agent_set_spass(agent *a, const char *str, int remove_spass);

/** Get alphabet of specified ID */
extern int agent_get_alphabet(agent *a, int id, const char **alphabet);

/** Get user warnings */
extern int agent_get_warnings(agent *a, int *warnings, int *failures);

/** Read prompt for given passcode */
extern int agent_get_prompt(agent *a, const num_t counter, char **reply);

/** Query for single passcode */
extern int agent_get_passcode(agent *a, num_t counter, char *reply); 

/** Try to authenticate */
extern int agent_authenticate(agent *a, const char *passcode); 

/** Skip to given counter */
extern int agent_skip(agent *a, const num_t counter); 

/** Update latest skipped password */
extern int agent_update_latest_card(agent *a, const num_t latest_card);

#endif
