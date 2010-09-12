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

static char num_overflow = 0;

#define num_set_overflow() _num_set_overflow(__FILE__, __LINE__)
void _num_set_overflow(const char *file, int location)
{
	printf("(%s:%d Overflow!)", file, location);
	num_overflow = 1;
}

static inline void num_clear_overflow(void)
{
	num_overflow = 0;
}

static inline char num_test_overflow(void)
{
	return num_overflow;
}





num_t num_lshift(const num_t arg)
{
	const num_t r = {
		.hi = arg.hi << 1 | (arg.lo >> 63),
		.lo = arg.lo << 1,
	};

	return r;
}

num_t num_rshift(const num_t arg)
{
	const num_t r = {
		.lo = arg.lo >> 1 | (arg.hi << 63),
		.hi = arg.hi >> 1,
	};

	return r;
}

num_t num_and(const num_t arg1, const num_t arg2)
{
	const num_t r = { 
		.hi = arg1.hi & arg2.hi,
		.lo = arg1.lo & arg2.lo
	};
	return r;
}

int num_cmp_i(const num_t arg1, const uint64_t arg2)
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
	num_t r = {
		.lo = arg1.lo + arg2.lo,
		.hi = arg1.hi + arg2.hi
	};

	if (r.hi < arg1.hi)
		num_set_overflow();

	if (r.lo < arg1.lo) {
		r.hi += 1;
		if (r.hi < 1)
			num_set_overflow();
	}

	return r;
}

num_t num_sub(const num_t arg1, const num_t arg2)
{
	num_t r = {
		.lo = arg1.lo - arg2.lo,
		.hi = arg1.hi - arg2.hi
	};

	/* Overflow in high subtraction */
	if (r.hi > arg1.hi)
		num_set_overflow();

	/* Overflow in low subtraction */
	if (r.lo > arg1.lo) {
		const uint64_t tmp = r.hi - 1;
		if (tmp > r.hi)
			num_set_overflow();
		r.hi = tmp;
	}
	return r;
}

num_t num_mul_i(num_t arg1, const uint64_t arg2)
{
	int i;
	int can_overflow = 0;
	num_t reply = num_zero();
	num_t r = num_i(arg2);
	for (i=0; i<128; i++) {
		if (arg1.lo & 0x01) {
			if (can_overflow)
				num_set_overflow();
			reply = num_add(reply, r);
		}

		arg1 = num_rshift(arg1);

		if (r.hi & 0x8000000000000000ULL)
			can_overflow = 1;
		r = num_lshift(r);
	}
	return reply;
}

uint64_t num_div_i(num_t *result, const num_t divwhat, const uint64_t divby)
{
	int i;
	uint64_t remainder = 0;

	*result = divwhat;
	char overflow = 0;
	for (i = 0; i < 128; i++) {
		if (remainder & 0x8000000000000000ULL)
			overflow = 1;
		remainder <<= 1;

		if (result->hi & 0x8000000000000000ULL)
			remainder |= 1;

		*result = num_lshift(*result);
		if (overflow) {
			remainder = 0xFFFFFFFFFFFFFFFFULL - divby + 1 + remainder;
			result->lo |= 1;
			overflow = 0;
		} else if (remainder >= divby) {
			remainder -= divby;
			result->lo |= 1;
		}
	}
	return remainder;
}


/***********************************************
 * Conversions
 **********************************************/

/* Returns string containing number in human-readable endianness */
static inline int _num_get_str(const num_t arg, char *buff, const int base)
{
	/* To string (Decimal) */
	assert(base == 16 || base == 10);
	assert(buff);

	num_t value = arg;
	uint64_t rest;

	char buf_tmp[55] = {0};
	char *bufpos = buf_tmp + 53;

	if (num_cmp_i(value, 0) == 0) {
		strcpy(buff, "0");
		return 0;
	}

	while (num_cmp_i(value, 0) != 0) {
		rest = num_div_i(&value, value, base);
		--bufpos;
		if (base == 10) {
			*bufpos = rest + '0';
		} else {
			if (rest <= 9)
				*bufpos = rest + '0';
			else {
				*bufpos = rest - 10 + 'A';
			}
		}
	}
	strcpy(buff, bufpos);
	return 0;
}

static inline int _num_set_str(num_t *arg, const char *str, const int base)
{
	assert(base == 16 || base == 10);

	unsigned char byte;
	int i;
	*arg = num_zero();

	switch (base) {
	case 10:
	{
		/* We must take care of overflow nicely */
		num_clear_overflow();

		for (i=0; i < 39 && str[i]; i++) {
			if (str[i] < '0' || str[i] > '9') {
				return 1;
			}

			/* Shift, then add new digit */
			*arg = num_mul_i(*arg, 10);
			*arg = num_add(*arg, num_i(str[i] - '0'));

			if (num_test_overflow())
				return 1;
		}
		if (str[i] || i>39 || i<1) {
			/* Garbage at the end or no data at all */
			return 1;
		}

		return 0;
	}
	case 16:
		for (i=0; i<32 && str[i]; i++) {
			/* Shift */
			for (byte=0; byte < 4; byte++) {
				*arg = num_lshift(*arg);
			}

			if (str[i] >= '0' && str[i] <= '9')
				byte = str[i] - '0';
			else if (str[i] >= 'A' && str[i] <= 'F')
				byte = 10 + str[i] - 'A';
			else if (str[i] >= 'a' && str[i] <= 'f')
				byte = 10 + str[i] - 'a';

			else {
				return 1;
			}
			
			*arg = num_add(*arg, num_i(byte));
		}

		if (str[i] || i > 32 || i < 1) {
			return 1;
		}

		return 0;
	default:
		return 1;
	}
}

int num_export(const num_t num, char *buff, enum num_str_type t) 
{
	int ret;
/* static inline int _num_get_str(const num_t arg, char *buff, const int base)
 */
	assert(buff);

	switch (t) {
	case NUM_FORMAT_DEC:
		ret = _num_get_str(num, buff, 10);
		return ret;

	case NUM_FORMAT_PPP_HEX:
	{
		char bin[16];
		int i;
		num_export(num, bin, NUM_FORMAT_BIN);
		for (i = 0; i < 16; i++) {
			snprintf(buff + i * 2,  3, "%02hhX", bin[i]);
		}
		
		return 0;
	}

	case NUM_FORMAT_HEX:
	{
		char bin[16];
		int i;
		num_export(num, bin, NUM_FORMAT_BIN);
		for (i = 0; i < 16; i++) {
			snprintf(buff + i * 2,  3, "%02hhX", bin[15 - i]);
		}
		
		return 0;
	}

	case NUM_FORMAT_BIN:
		/* FIXME: This depends on endiannes. Result should always look like
		 * on an little-endian machine. Add some #ifs */
		memcpy(buff  , &num.lo, 8);
		memcpy(buff+8, &num.hi, 8);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return 1;
	}
	return 1;
}

/* 
 * Parse either decimal or hex into a num_t type.
 * 0 - success
 */
int num_import(num_t *num, const char *buff, enum num_str_type t)
{
	int ret;
	switch (t) {
	case NUM_FORMAT_DEC:
		ret = _num_set_str(num, buff, 10);
		return ret;

	case NUM_FORMAT_PPP_HEX:
	case NUM_FORMAT_HEX:
		ret = _num_set_str(num, buff, 16);
		return ret;

	case NUM_FORMAT_BIN:
		memcpy(&num->lo, buff  , 8);
		memcpy(&num->hi, buff+8, 8);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return 1;
	}
	return 1;
}


/*****************************
 * Printing helpers 
 *****************************/
void num_print_hex(const num_t num, int msb)
{
	char hex[35] = {0};
	int i;

	if (msb) {
		i = num_export(num, hex, NUM_FORMAT_HEX);
	} else {
		i = num_export(num, hex, NUM_FORMAT_PPP_HEX);		
	}
	
	printf("%s", hex);

	assert(i==0);
	if (i != 0)
		return;

	memset(hex, 0, sizeof(hex));
}

void num_print_dec(const num_t arg)
{
	int ret;
	char buf[50];
	ret = num_export(arg, buf, NUM_FORMAT_DEC);
	assert(ret == 0);
	if (ret != 0)
		return;
	printf("%s", buf);
}

