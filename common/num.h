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
 *   Additional (to GMP) operations on long numbers. In future might be
 *   used as a place for functions which will be supposed to drop 
 *   dependency on GMP. num_init sets GMP allocation routines which
 *   safely clean up memory.
 **********************************************************************/

#ifndef _NUM_H_
#define _NUM_H_

/* Configuration */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <assert.h>

/******************************
 * Own 128 bit library test
 *
 * This is a try to drop dependency on GMP. 
 * This program doesn't need arbitrary precision mathematics
 * 128bit unsigned integers are more then enough. I'll start
 * implementation by assuming I've got 64bit available and it
 * can be later tweaked if something more portable is required
 *
 * Functions must work like this:
 * (destination, arg1, arg2)
 * And destination can equal arg1
 */

typedef struct {
	uint64_t hi;
	uint64_t lo;
} num_t;

/*****************************
 * Setters 
 *****************************/
static inline num_t num_ii(uint64_t arg1, uint64_t arg2) {
	const num_t a = {arg1, arg2};
	return a;
}

#define num_i(x) num_ii(0L, x)

static inline void num_init_(num_t *n) {
	n->hi = 0;
	n->lo = 0;
}

/*****************************
 * Logical operations
 *****************************/
extern num_t num_and(const num_t arg1, const num_t arg2);
extern num_t num_lshift(const num_t arg);
extern num_t num_rshift(const num_t arg);

/*****************************
 * Comparisons
 *****************************/
extern int num_cmp_i(const num_t arg1, const uint64_t arg2);
extern int num_cmp(num_t arg1, num_t arg2);
#define num_sgn(a) num_cmp((a), num_i(0))


/*****************************
 * Arithmetic operations
 *****************************/
extern num_t num_add(const num_t arg1, const num_t arg2);
extern num_t num_sub(const num_t arg1, const num_t arg2);
extern num_t num_mul_i(num_t arg1, const uint64_t arg2);
extern uint64_t num_div_i(num_t *result, const num_t divwhat, const uint64_t divby);

#define num_add_i(a, b) num_add((a), num_i(b))
#define num_sub_i(a, b) num_sub((a), num_i(b))
#define num_clear(a) do { (a) = num_i(0); } while (0)





/************************************************
 * Conversions. This functions should work for both
 * GMP and our own implementation.
 *
 * 1) Printing decimal for user
 * 2) Printing HEX for user (ppp compat)
 * 3) Printing HEX for debug (msb)
 * 4) Converting to/from binary for encryption
 * Implement as storing in buffer (preallocated
 ************************************************/

/* Exports num_t into binary, hex string or LSB first PPP compatible HEX string 
 * Minimal safe length of buff for all options is 39 bytes. 
 * Binary is not \0 padded and it's length is 16 bytes.
 * 0 - OK
 * 1 - Error
 */
enum num_str_type { NUM_FORMAT_DEC, NUM_FORMAT_HEX, NUM_FORMAT_PPP_HEX, NUM_FORMAT_BIN };
extern int num_export(const num_t num, char *buff, enum num_str_type t);

/* 
 * Parse either decimal or hex into a num_t type.
 * 0 - success
 */
extern int num_import(num_t *num, const char *buff, enum num_str_type t);

/* Helpers */
/* Set MSB to 1 for PPPv3 compatibility */
extern void num_print_hex(const num_t num, int msb);
extern void num_print_dec(const num_t arg);

/* This function set's GMP memory allocation routines 
 * to safer versions which cleanup deallocated memory */
extern void num_init(void);

#endif
