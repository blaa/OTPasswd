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

/*
 * Data is transferred via pipe. Client program has a 
 * pair of descriptors used for communication and agent
 * has it hooked up to the stdin/stdout.
 *
 * 1) Data files may never be locked during transmission
 * 2) Communication is request/reply based and never initiated
 *    by agent.
 * 3) Therefore operations must be atomic.
 * 4) User interface should be possibly as high-level as possible 
 *    so writting future interfaces will be simple.
 * 5) Protocol must be trivial too parse; use static buffer sizes
 *    everywhere.
 * 6) Some operations like key generation require multiple 
 *    request/replies, therefore agent connection must be
 *    persistent between requests.
 * 7) Request must allow localization. Therefore passcard
 *    generation, alphabet list generation etc. must be done
 *    at the frontend side. Agent at minimum must return 
 *    single passcodes.
 */


/*
 * Agent keeps in memory single copy of state
 * either loaded by status query or fresh generated.
 *
 * Possible operations and it's arguments:
 * 1. Key
 *  a) Generate key
 *     Parameters: flags: Salted / not salted, alphabet, codelength
 *     - Create new state and generate key
 *     - Keep state in memory, in reply return first passcard
 *     - if next action is "Save" - (lock, save, unlock), otherwise dispose of it.
 *  b) Remove key
 *     - Lock state
 *     - remove user entry
 *     - Unlock state
 *     Warnings about enforced OTP should be made by UI
 * 2. Status
 *    - Lock state file
 *    - Read user state
 *    - Unlock state file
 *    - Put information available (check policy) into struct
 *    - dispose of user state
 *    - send reply
 *    Gives access to:
 *    key, counter, alphabet, flags, last_passcard...
 *    Agent client caches this information until disconnect 
 * 3. String query 
 *    a) Query passcode (given unsalted passcode number)
 *    b) Query passcard (given passcard number)
 *    c) Query passpage (returns LaTeX)
 *    d) Query current prompt
 *    e) Query warnings
 *
 * 4. Configuration
 *  c) Enable/disable flags:
 *     show, salt (during key generation)
 *  x) Select/list alphabet
 *  x) Select passcode length
 *  x) Enable/disable otpasswd for account
 *  a) Set contact 
 *  b) Set label

 *  f) Configure static password
 * 5. Skip
 *  a) Passcode
 *  b) Passcard
 * 6. Authenticate
 *
 * 10) Miscellenous:
 *  a) Return current warnings
 *  b) Return prompt
 *
 */

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

	/*** Various errors ***/
	AGENT_ERR_MEMORY,
	AGENT_ERR_POLICY,
	AGENT_ERR_SERVER_INIT,
	AGENT_ERR_PROTOCOL_MISMATCH,
	AGENT_ERR_DISCONNECT,

	/*** Coding/assumptions errors ***/
	AGENT_ERR_MUST_CREATE_STATE,
	AGENT_ERR_MUST_DROP_STATE,
	AGENT_ERR_NO_STATE,
};

/*** Basic routines ***/
extern int agent_connect(agent **a_out, const char *agent_executable);
extern int agent_disconnect(agent *a);
extern int agent_set_user(agent *a, char *username);

/** Return translated description of last error */

extern const char *agent_strerror(int error);

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
extern int agent_flag_get(agent *a);


/** Status query */

/* Set of getters/setters */
extern int agent_get_key(const agent *a, char *key);

enum AGENT_TYPE {
	AGENT_COUNTER_UNSALTED,
	AGENT_COUNTER_SALTED,
};
extern int agent_get_num(const agent *a, num_t *key, int type);
extern int agent_get_int(agent *a, int field, int *reply);

/* Config query */
extern int agent_get_passcode(const agent *a, int field, char **reply); 

// void agent_set(agent *a);


#endif
