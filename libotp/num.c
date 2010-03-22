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
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "print.h"
#include "num.h"

/******************************
 * Own 128 bit library test
 *****************************/
#if !USE_GMP
void num_overflow(void)
{
	printf("Overflow!\n");
}

num_t num_lshift(const num_t arg)
{
	num_t r;
	r.hi = arg.hi << 1;
	if (arg.lo & 0x8000000000000000ULL)
		r.hi |= 1;
	r.lo = arg.lo << 1;
	return r;
}

num_t num_rshift(const num_t arg)
{
	num_t r;

	r.lo = arg.lo >> 1;

	if (arg.hi & 1)
		r.lo |= 0x8000000000000000ULL;
	r.hi = arg.hi >> 1;
	return r;
}

num_t num_and(const num_t arg1, const num_t arg2)
{
	num_t r;
	r.hi = arg1.hi & arg2.hi;
	r.lo = arg1.lo & arg2.lo;
	return r;
}

int num_cmp_i(num_t arg1, uint64_t arg2)
{
	if (arg1.hi || arg1.lo > arg2)
		return 1;
	if (arg1.lo == arg2)
		return 0;
	
	return -1;
}

int num_cmp(const num_t arg1, const num_t arg2)
{
	if (arg1.hi > arg2.hi)
		return 1;
	if (arg1.hi < arg2.hi)
		return -1;

	if (arg1.lo > arg2.lo)
		return 1;
	if (arg1.lo < arg2.lo)
		return -1;
	
	return 0;
}

num_t num_add(const num_t arg1, const num_t arg2)
{
	num_t r;
	r.lo = arg1.lo + arg2.lo;
	r.hi = arg1.hi + arg2.hi;
	if (r.hi < arg1.hi)
		num_overflow();

	if (r.lo < arg1.lo) {
		r.hi += 1;
		if (r.hi < 1)
			num_overflow();
	}

	return r;
}

num_t num_sub(num_t arg1, num_t arg2)
{
	num_t r;
	r.lo = arg1.lo - arg2.lo;
	r.hi = arg1.hi - arg2.hi;
	if (r.hi > arg1.hi)
		num_overflow();

	if (r.lo > arg1.lo) {
		r.hi -= 1;
		if (r.hi < 1)
			num_overflow();
	}
	return r;
}

num_t num_mul_i(num_t arg1, const uint64_t arg2)
{
	int i;
	int can_overflow = 0;
	num_t reply = num_i(0);
	num_t r = num_i(arg2);
	for (i=0; i<128; i++) {
		const int bit = arg1.lo & 1;
		if (bit) {
			if (can_overflow)
				num_overflow();
			reply = num_add(reply, r);
		}

		arg1 = num_rshift(arg1);

		if (r.hi & 0x8000000000000000ULL)
			can_overflow = 1;
		r = num_lshift(r);
	}
	return reply;
}

uint64_t num_div_i(num_t *result, num_t divwhat, uint64_t divby)
{
	uint64_t remainder = 0;
	num_t quotient;

	quotient = divwhat;

	/* Longhand div algorithm */
	int i;
	for (i = 0; i < 128; i++) {
		remainder <<= 1;
		remainder |= quotient.hi & 0x8000000000000000ULL ? 1 : 0;

		quotient = num_lshift(quotient);
		if (remainder >= divby) {
			remainder -= divby;
			quotient.lo |= 1;
		}
	}

	*result = quotient;
	return remainder;
}

#endif



char *num_get_str(const num_t arg, const int base)
{
	/* To string (Decimal) */
	char *buf;
	char *bufpos;

	assert(base == 16 || base == 10);

#if USE_GMP
	buf1 = mpz_get_str(NULL, base, arg);
	assert(buf1);
	return buf1;
#else

	buf = malloc(45); /* 32 + 1, but must fit base 10! */
	bufpos = buf+44;
	if (!buf)
		return NULL;

	num_t value = arg;
	uint64_t rest;

	while (num_cmp_i(value, 0) != 0) {
		if (base == 10) {
			rest = num_div_i(&value, value, 10);

			--bufpos;
			*bufpos = rest + '0';
		} else {
			rest = num_div_i(&value, value, 16);
			--bufpos;
			if (rest <= 9)
				*bufpos = rest + '0';
			else {
				*bufpos = rest - 10 + 'A';
			}
		}
	}
	return bufpos;
#endif
}

int num_set_str(num_t *arg, const char *str, const int base)
{
	assert(base == 16);



#if USE_GMP
	int ret;
	if (base == 10) {
		ret = gmp_sscanf(str, "%Zu", *arg);
		return ret;
	} else if (base == 16) {
		printf("Unimplemented!\n");
		/* ret = gmp_sscanf(str, "%ZX", *arg); */
		assert(0);
	} else {
		assert(0);
	}

	return 0;

#else


	unsigned char byte;
	int i;
	*arg = num_i(0);
	for (i=0; str[i+1]; i+=2) {
		if ((str[i] < '0' || str[i] > '9') && (str[i] < 'A' || str[i] > 'F'))
			break;
		if ((str[i+1] < '0' || str[i+1] > '9') && (str[i+1] < 'A' || str[i+1] > 'F'))
			break;

		byte = (str[i]-'A') << 4;
		byte |= str[i+1];
		*arg = num_add(*arg, num_i(byte));
		for (byte=0; byte < 8; i++)
			*arg = num_lshift(*arg);
	}
	if (str[i+1] || i >=32) {
		printf("Error while reading hex string\n");
		return 1;
	}
	return 0;
#endif
}



void num_testcase_(void)
{
#if !USE_GMP
	int failed = 0;
	num_t a,b,c;
	uint64_t r;
	int i;

	printf("*** Shift test: ");
	a = num_i(1);
	for (i=0; i<127; i++) {
		a = num_lshift(a);
	}
	for (i=0; i<127; i++) {
		a = num_rshift(a);
	}

	if (num_cmp_i(a, 1) != 0) {
		failed++;
		printf("Shift test failed\n");
	} else 
		printf("Shift test OK\n");



	a = num_i(18446744073709551615ULL);
	b = num_i(1);
	c = num_add(a, b);

	printf("Division:\n");
	a = num_ii(18446744073709551615ULL, 18446744073709551615ULL);
	r = num_div_i(&c, a, 65);

	printf("Result = "); num_print_dec(c);
	printf("Rest=%llu\n", r);

	printf("Multiplication:\n");
	a = num_ii(50, 50);
	c = num_mul_i(a, 184467440000000000ULL);

	printf("Result = "); num_print_dec(c);
#endif
}



/********************************
 * Helpers for GMP follow
 *******************************/

/* All functions are inline currently and testcase
 * was moved away to testcases.c */
#if USE_GMP
static void *allocate_function(size_t alloc_size)
{
	void *tmp = malloc(alloc_size);
	if (!tmp) {
		print(PRINT_ERROR, "Not enough memory!\n");
		exit(EXIT_FAILURE);
	}
	return tmp;
}

static void free_function(void *ptr, size_t size)
{
	memset(ptr, 0, size);
	free(ptr);
}

static void *reallocate_function(void *ptr, size_t old_size, size_t new_size)
{
	const size_t copy_size = old_size < new_size ? old_size : new_size;
	void *new_ptr = allocate_function(new_size);
	memcpy(new_ptr, ptr, copy_size);
	free_function(ptr, old_size);
	return new_ptr;
}
#endif

void num_init(void)
{
#if USE_GMP
	mp_set_memory_functions(allocate_function,
				reallocate_function,
				free_function);
#endif
}
