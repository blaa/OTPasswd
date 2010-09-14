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
 * Functions used internally by agent and agent interface.
 * Private agent interface.
 **********************************************************************/

#ifndef _AGENT_PRIVATE_H_
#define _AGENT_PRIVATE_H_

#define AGENT_INTERNAL 1

#define AGENT_PATH "otpagent"
#define AGENT_PROTOCOL_VERSION (0xDEAD0000 | 0x00)

#include <unistd.h>
#include <sys/types.h> /* pid_t etc. */

#include "ppp.h"
#include "num.h" /* num_t type */

enum AGENT_REQUEST {
	/*** Generic requests/messages ***/

	/** Informs client that agent started.
	 * Args: status is non-zero on error.
	 */
	AGENT_REQ_INIT = 1,

	/** Asks server to quit
	 * Arguments ignored
	 */
	AGENT_REQ_DISCONNECT,	      

	/** Set username of which we're going
	 * to mess state data. Can be used exclusively
	 * by privileged user */
	AGENT_REQ_USER_SET,

	/** Agent reply 
	 * Arguments depends on what is it reply for.
	 */
	AGENT_REQ_REPLY,

	/*** State related request ***/
	/** Call before generating new key */
	AGENT_REQ_STATE_NEW,

	/** Call before doing state queries or to check if state exists */
	AGENT_REQ_STATE_LOAD,

	/** Store key */
	AGENT_REQ_STATE_STORE,

	/** Forget loaded/new state */
	AGENT_REQ_STATE_DROP,


	/** Generate key */
	AGENT_REQ_KEY_GENERATE,

	/** Remove key */
	AGENT_REQ_KEY_REMOVE,

	/* Flags */
	AGENT_REQ_FLAG_ADD,
	AGENT_REQ_FLAG_CLEAR,
	AGENT_REQ_FLAG_GET,

	/* Verify that the state is consistent with policy */
	AGENT_REQ_VERIFY,

	/* Universal getters */
	AGENT_REQ_GET_NUM,
	AGENT_REQ_GET_INT,
	AGENT_REQ_GET_STR,
	
	/* Precise getters */
	AGENT_REQ_GET_ALPHABET,
	AGENT_REQ_GET_WARNINGS,

	/* Get passcode of specified number */
	AGENT_REQ_GET_PASSCODE,

	/* Get prompt for specified number */
	AGENT_REQ_GET_PROMPT,

	/* State field setters. Can work with new 
	 * states or when no state exists (then they perform
	 * operation atomically) */
	AGENT_REQ_SET_NUM,
	AGENT_REQ_SET_INT,
	AGENT_REQ_SET_STR,

	AGENT_REQ_SET_SPASS,

	/* Authenticate user with password */
	AGENT_REQ_AUTHENTICATE,

	/* Skip to passcode */
	AGENT_REQ_SKIP,

	/* Update latest printed card */
	AGENT_REQ_UPDATE_LATEST,
};


/* Maximal size of any transferred argument string.
 * 255 should be more then enough as label/contact don't exceed 80 bytes.
 * The only thing which will be limited is static password size 
 */
#define AGENT_ARG_MAX 255

struct agent_header {
	/* Ensures both executables are having the same
	 * version */
	int protocol_version;

	/* Request type + Reply type 
	 * Example: Set int field.
	 */
	int type;

	/* Reply status/error code */
	int status;

	/* Generic arguments */
	/* int_arg example: What field to set 
	 * int_arg2 example: the value of a field
	 */
	int int_arg;             
	int int_arg2;
	num_t num_arg;

	/* This must be large enough to contain:
	 * passwords, contact/label, alphabet reply (under 128 chars)
	 */
	char str_arg[AGENT_ARG_MAX];
};


typedef struct {
	/** Descriptors used for connection */
	int in, out;

	/** Child PID */
	pid_t pid;

	/** Error while communicating with agent? */
	int error;
	
	/** Send header */
	struct agent_header shdr;

	/** Recv header */
	struct agent_header rhdr;

	/** Username owning state; used only if ran by privileged user */
	char *username;

	/** Is the state just being generated? It may alter execution of some functions (flags). */
	int new_state;

	/** State currently held by agent
	 * Currently only freshly generated key can be
	 * stored here */
	state *s;
} agent;

/***
 * Private helper functions 
 ***/

/** Configure agent interface to run as server */
extern int agent_server(agent **a_out);

/** Prepares header for sending. */
extern void agent_hdr_init(agent *a, int status);
/** Clear all data from header */
extern void agent_hdr_sanitize(agent *a);
/** Sets NUM argument inside agent_interface header */
extern void agent_hdr_set_num(agent *a, const num_t *num_arg);
/** Sets integer argument inside agent_interface header */
extern void agent_hdr_set_int(agent *a, int int_arg, int int_arg2);
/** Sets string argument inside agent_interface header */
extern int agent_hdr_set_str(agent *a, const char *str_arg);
/** Like agent_hdr_set_str but allows \x00 bytes inside str */
extern int agent_hdr_set_bin_str(agent *a, const char *str_arg, int length);


/** Send header to the agent */
extern int agent_hdr_send(const agent *a);
/** Receive header from the agent */
extern int agent_hdr_recv(agent *a);

/** Send header of query type and return result */
extern int agent_query(agent *a, int action);

/** Wait for incoming data; returns 0 if anything arrived */
extern int agent_wait(agent *a);

/** Displays header information */
extern void agent_hdr_debug(const struct agent_header *hdr);

/***
 * Getters
 ***/
/** Type getter */
static inline int agent_hdr_get_type(const agent *a) {
	return a->rhdr.type;
}

/** Type setter */
static inline void agent_hdr_set_type(agent *a, int type) {
	a->shdr.type = type;
}


/** Status getter */
static inline int agent_hdr_get_status(const agent *a) {
	return a->rhdr.type;
}

/** Status setter */
static inline void agent_hdr_set_status(agent *a, int status) {
	a->shdr.status = status;
}


/** Int argument getter */
static inline int agent_hdr_get_arg_int(const agent *a) {
	return a->rhdr.int_arg;
}

/** Second int argument getter */
static inline int agent_hdr_get_arg_int2(const agent *a) {
	return a->rhdr.int_arg2;
}

/** num_t argument getter */
static inline num_t agent_hdr_get_arg_num(const agent *a) {
	return a->rhdr.num_arg;
}

/** String argument getter */
static inline const char *agent_hdr_get_arg_str(const agent *a) {
	return a->rhdr.str_arg;
}


/* Now include also public interface */
#include "agent_interface.h"


#endif
