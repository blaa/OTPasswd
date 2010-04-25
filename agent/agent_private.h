#ifndef _AGENT_PRIVATE_H_
#define _AGENT_PRIVATE_H_

#define AGENT_INTERNAL 1

#define AGENT_PATH "otpagent"
#define AGENT_PROTOCOL_VERSION (0xDEAD0000 | 0x00)

#include <unistd.h>
#include <sys/types.h> /* pid_t etc. */

#include "num.h" /* num_t type */

/* Musn't collide with PPP errors from ppp_common.h */
enum AGENT_ERROR {
	AGENT_OK=0,
	AGENT_ERR=5000,
	AGENT_ERR_MEMORY,
	AGENT_ERR_SERVER_INIT,
	AGENT_ERR_PROTOCOL_MISMATCH,
	AGENT_ERR_DISCONNECT,
};

enum AGENT_REQUEST {
	/*** Additional messaging ***/

	/** Informs client that agent started.
	 * Args: status is non-zero on error.
	 */
	AGENT_REQ_INIT = 1,           

	/** Asks server to quit
	 * Arguments ignored
	 */
	AGENT_REQ_DISCONNECT,	      

	/** Agent reply 
	 * Arguments depends on what is it reply for.
	 */
	AGENT_REQ_REPLY,

	/** Generate key */
	AGENT_REQ_KEY_GENERATE,

	/** Remove key */
	AGENT_REQ_KEY_REMOVE,

	/** Store key */
	AGENT_REQ_KEY_STORE,

	/** Read state from disc */
	AGENT_REQ_READ_STATE,

	AGENT_REQ_FLAG_SET,
	AGENT_REQ_FLAG_CLEAR,
	AGENT_REQ_FLAG_CHECK,
	AGENT_REQ_FLAG_GET, /* <-- FIX */

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

	/* Request type + Reply type */
	int type;

	/* Reply status/error code */
	int status;

	/* Generic arguments */
	int int_arg;
	num_t num_arg;

	/* This must be large enought to contain:
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
} agent;

/***
 * Private helper functions 
 ***/

/** Configure agent interface to run as server */
extern int agent_server(agent **a_out);

/** Prepares header for sending */
extern int agent_hdr_set(agent *a, int status, 
                         int int_arg, const num_t *num_arg,
                         const char *str_arg);

extern int agent_hdr_send(const agent *a);
extern int agent_hdr_recv(agent *a);
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
