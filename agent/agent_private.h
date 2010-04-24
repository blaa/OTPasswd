#ifndef _AGENT_PRIVATE_H_
#define _AGENT_PRIVATE_H_

#define AGENT_INTERNAL 1

#define AGENT_PATH "otpagent"
#define AGENT_PROTOCOL_VERSION (0xDEAD0000 | 0x00)

#include <unistd.h>
#include <sys/types.h> /* pid_t etc. */

#include "num.h" /* num_t type */

enum AGENT_ERROR {
	AGENT_OK=0,
	AGENT_ERR=5000,
	AGENT_ERR_MEMORY,
	AGENT_ERR_POLICY,
};

enum AGENT_REQUEST {
	/** Generate key */
	AGENT_REQ_KEY_GENERATE = 1,

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
	/* Descriptors used for connection */
	int in, out;

	/* Child PID */
	pid_t pid;

	/* Error while communicating with agent? */
	int error;

	struct agent_header hdr;
} agent;

/* Private helper functions */
extern int agent_send_header(const agent *a);
extern int agent_recv_header(agent *a);
extern int agent_query(agent *a, int action);


/* Now include also public interface */
#include "agent_interface.h"


#endif
