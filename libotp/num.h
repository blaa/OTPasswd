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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#define USE_GMP 0

#if USE_GMP
#include <gmp.h>
#endif

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

#include <inttypes.h>

#if !USE_GMP

typedef struct {
	uint64_t hi;
	uint64_t lo;
} num_t;

/* Setters */
static inline num_t num_ii(uint64_t arg1, uint64_t arg2) {
	const num_t a = {arg1, arg2};
	return a;
}

#define num_i(x) num_ii(0L, x)

static inline void num_init_(num_t *n) {
	n->hi = 0;
	n->lo = 0;
}

/* Logical operations */
extern num_t num_and(const num_t arg1, const num_t arg2);
extern num_t num_lshift(const num_t arg);
extern num_t num_rshift(const num_t arg);

/* Comparison */
extern int num_cmp_i(const num_t arg1, const uint64_t arg2);
extern int num_cmp(num_t arg1, num_t arg2);

/* Arithmetic operations */
extern num_t num_add(const num_t arg1, const num_t arg2);
extern num_t num_sub(const num_t arg1, const num_t arg2);
extern num_t num_mul_i(num_t arg1, const uint64_t arg2);
extern uint64_t num_div_i(num_t *result, num_t divwhat, uint64_t divby);

extern void num_testcase_(void);


/* Macros used to substitute GMP for our own function set */
typedef num_t mpz_t;
#define mpz_and(c, a, b) do { c = num_and(a, b); } while (0)
#define mpz_add(c, a, b) do { c = num_add(a, b); } while (0)
#define mpz_add_ui(c, a, b) do { c = num_add(a, num_i(b)); } while (0)
#define mpz_sub(c, a, b) do { c = num_sub(a, b); } while (0)
#define mpz_sub_ui(c, a, b) do { c = num_sub(a, num_i(b)); } while (0)

#define mpz_mul(c, a, b) do { c = num_mul_i(a, num_i(b)); } while (0)
#define mpz_mul_ui(c, a, b) do { c = num_mul_i(a, b); } while (0)
#define mpz_fdiv_q_ui(quot, divwhat, divby) num_div_i(&quot, divwhat, divby)
#define mpz_div_ui(quot, divwhat, divby) num_div_i(&quot, divwhat, divby)

#define mpz_set(a, b) do { a = b; } while(0)
#define mpz_set_ui(a, b) do { a = num_i(b); } while(0)

#define mpz_get_str(x, base, a) num_get_str(a, base)
#define mpz_set_str(a, b, base) num_set_str(&a, b, base)
#define mpz_init_set_str(a, b, base) do { a = num_get_hex(a, b); } while (0)

#define mpz_cmp(a, b) num_cmp(a, b)
#define mpz_cmp_ui(a, b) num_cmp(a, num_i(b))
#define mpz_sgn(a) mpz_cmp(a, num_i(0))

#define mpz_clear(a) do { a = num_i(0); } while (0)
#define mpz_init(a) do { a = num_i(0); } while (0)
#define mpz_set_d(a, b) do { a = num_i(b); } while (0)
#define mpz_init_set(a, b) do { a = b; } while (0)


#endif



/************************************************
 * Helpers. This functions should work for both
 * GMP and our own implementation.
 ************************************************/

/* Converts num_t into string representation in either base 10
 * or base 16. Returned string is allocated and should be freed. */
extern char *num_get_str(const num_t arg, const int base);
/* Parses input string in base 10 or 16, returns num. */
extern int num_set_str(num_t *arg, const char *str, const int base);


static inline void num_from_bin(mpz_t num, const unsigned char *data, const size_t length)
{
	/* Store data as LSB - to match pppv3 */
#if USE_GMP
	mpz_import(num, 1, 1, length, -1 /* LSB to match ppp behaviour */ , 0, data);
#else
	memcpy(&num, data, length);
#endif
}

static inline void num_to_bin(const mpz_t num, unsigned char *data, const size_t length)
{
#if USE_GMP
	size_t size = 1;
	/* Handle 0 numbers; otherwise nothing would be written to data */
	if (mpz_cmp_si(num, 0) == 0)
		memset(data, 0, length);
        else 
		(void) mpz_export(data, &size, 1, length, -1, 0, num);
	assert(size == 1);
#else
	memcpy(data, &num, length);
#endif
}

/* Convert number to hex which conforms with PPPv3 methods */
static inline void num_to_hex(const mpz_t num, char *data, const unsigned int length)
{
	unsigned char bin[32];
	int i;
	assert(length == 65 || length == 33); /* Key or counter */

	const int bin_len = (length-1) / 2;

	num_to_bin(num, bin, bin_len);

	for (i = 0; i < bin_len; i++)
		snprintf(data + i * 2,  3, "%02X", bin[i]);
}

static inline void num_print_hex(const mpz_t num, const unsigned int length)
{
	unsigned char bin[32];
	int i;

	assert(length == 32 || length == 64); /* Key or counter */

	const int bin_len = (length) / 2;

	num_to_bin(num, bin, bin_len);

	for (i = 0; i < bin_len; i++)
		printf("%02X", bin[i]);

	memset(bin, 0, sizeof(bin));

/* Alternative: 
	if (length == 32) 
		gmp_printf("%32Zd", arg);
	else
		gmp_printf("%64Zd", arg);
*/

}

#if USE_GMP
static inline void num_print_dec(const num_t arg)
{
	gmp_printf("%Zd", arg);
}

#else

static inline void num_print_dec(const num_t arg)
{
	/* To string (Decimal) */
	char *buf = num_get_str(arg, 10);
	if (!buf) 
		printf("ERROR");
	else
		printf("%s", buf);
}
#endif



/* This function set's GMP memory allocation routines 
 * to safer versions which cleanup deallocated memory */
extern void num_init(void);

#endif
