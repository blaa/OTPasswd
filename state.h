#ifndef _STATE_H_
#define _STATE_H_

#include <gmp.h>

/* Config */
#define STATE_FILENAME ".otpasswd"
#define STATE_BASE	62
/* State */
enum flags {
	FLAG_SHOW_PASSCODE = 1
};
	
typedef struct {
	/* 128 bit counter pointing at the next passcode
	 * which will be used for authentication */
	mpz_t counter;

	/* User secret sequence key */
	mpz_t sequence_key;

	/* Furthest printed passcode
	 * used for warnings */
	mpz_t furthest_printed;

	/* Number of bytes used for passcode (2 - 16) */
	unsigned int passcode_length;

	/* User flags */
	unsigned int flags;




	/* Not necessarily part of a user state, 
	 * this is data used for storing/restoring
	 * state information 
	 */
	
	char *filename;	/* Path to state file    */
	int fd;		/* State file descriptor */
	int lock_fd;	/* Is the file locked?   */
} state;


extern int state_init(state *s);
extern void state_fini(state *s);

extern int state_key_generate(state *s);
extern void state_inc(state *s);

extern void state_debug(const state *s);
extern int state_store(const state *s);
extern int state_load(state *s);

extern void state_testcase(void);

#endif 
