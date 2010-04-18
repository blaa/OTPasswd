#ifndef _AGENT_PRIVATE_H_
#define _AGENT_PRIVATE_H_

enum AGENT_ERROR {
	AGENT_OK=0,
	AGENT_ERR=500,
	AGENT_ERR_POLICY=501,
};

enum AGENT_REQUEST {
	/** Generate key */
	AGENT_REQ_KEY_GENERATE = 1,

	/** Remove key */
	AGENT_REQ_KEY_REMOVE,

	/** Store key */
	AGENT_REQ_KEY_STORE,

	/** Read state from disc */
	AGENT_REQ_UPDATE_STATE,
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

	/* Length of a request argument.
	 * This can be a password, contact, label etc.
	 */
	char argument[AGENT_ARG_MAX];

	/* Bytes in 'data' element */
	int bytes;

	/* Alternatively number of items (structs) in data */
	int items;
	void *data;
};

struct agent_reply_alphabet {
	int id;
	int policy_accepted;
	char chars[AGENT_ARG_MAX];
};

/* Reply containing warnings or error code + description */
struct agent_reply_string {
	int type;
	int code;
	char data[AGENT_ARG_MAX];
};


typedef struct {
	/* Descriptors used for connection */
	int in, out;

	/* Child PID */
	pid_t pid;

	struct agent_header hdr;
} agent;

#endif
