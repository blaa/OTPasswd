#ifndef _PPP_COMMON_H_
#define _PPP_COMMON_H_

/* Size of fields */
#define STATE_LABEL_SIZE 30
#define STATE_CONTACT_SIZE 60
#define STATE_STATIC_SIZE 32 /* binary SHA256 of static password */
#define STATE_ENTRY_SIZE 512 /* Maximal size of a valid state entry (single line) */
#define ROWS_PER_CARD 10

/* We must distinguish between locking problems (critical)
 * and non-existant state file (usually not critical) */
enum errors {
	PPP_NOMEM = 40,
	STATE_LOCK_ERROR = 45,
	STATE_PARSE_ERROR = 46,
	STATE_DOESNT_EXISTS = 47,	/* or it not a regular file */
	STATE_PERMISSIONS = 48,		/* Insufficient possibly */
	STATE_NUMSPACE = 49,		/* Counter too big */
	STATE_RANGE = 50,		/* For example negative key */
};


enum flags {
	FLAG_SHOW = 1,
	FLAG_SKIP = 2,
	FLAG_ALPHABET_EXTENDED = 4,
	FLAG_NOT_SALTED = 8,
};

#endif
