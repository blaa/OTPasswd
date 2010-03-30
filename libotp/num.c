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
static char overflow = 0;
void _num_overflow(const char *file, int location)
{
	printf("(%s:%d Overflow!)", file, location);
	overflow++;
}
#define num_overflow() _num_overflow(__FILE__, __LINE__)

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
	const num_t r = { 
		.hi = arg1.hi & arg2.hi,
		.lo = arg1.lo & arg2.lo
	};
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

num_t num_sub(const num_t arg1, const num_t arg2)
{
	num_t r;
	r.lo = arg1.lo - arg2.lo;
	r.hi = arg1.hi - arg2.hi;

	/* Overflow in high subtraction */
	if (r.hi > arg1.hi)
		num_overflow();

	/* Overflow in low subtraction */
	if (r.lo > arg1.lo) {
		const uint64_t tmp = r.hi - 1;
		if (tmp > r.hi)
			num_overflow();
		r.hi = tmp;
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


/***********************************************
 * Conversions
 **********************************************/

//enum num_str_type { NUM_FORMAT_DEC, NUM_FORMAT_HEX, NUM_FORMAT_PPP_HEX };
int num_export(const num_t num, char *buff, enum num_str_type t) 
{
#if USE_GMP
	switch (t) {
	case NUM_FORMAT_DEC:
		break;
	case NUM_FORMAT_HEX:
		break;
	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return ;1
	}

#else
	switch (t) {
	case NUM_FORMAT_DEC:
		break;
	case NUM_FORMAT_HEX:
		break;
	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		memcpy(data  , &num.lo, 8);
		memcpy(data+8, &num.hi, 8);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return ;1
	}
#endif
}

/* 
 * Parse either decimal or hex into a num_t type.
 * 0 - success
 */
int num_import(num_t *num, const char *buff, enum num_str_type t)
{
#if USE_GMP
	switch (t) {
	case NUM_FORMAT_DEC:
		break;
	case NUM_FORMAT_HEX:
		break;
	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		mpz_import(num, 1, 1, length, -1 /* LSB to match ppp behaviour */ , 0, data);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return ;1
	}

#else

	switch (t) {
	case NUM_FORMAT_DEC:
		break;
	case NUM_FORMAT_HEX:
		break;
	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		memcpy(&num.lo, buff  , 8);
		memcpy(&num.hi, buff+8, 8);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return ;1
	}
#endif
}


#if 0
void num_from_bin(mpz_t num, const unsigned char *data, const size_t length)
{
	/* Store data as LSB - to match pppv3 */
#if USE_GMP
	mpz_import(num, 1, 1, length, -1 /* LSB to match ppp behaviour */ , 0, data);
#else
//	memcpy(&num, data, length);
	assert(length == 16);
	memcpy(&num.lo, data  , 8);
	memcpy(&num.hi, data+8, 8);

#endif
}

/* Converts number to HEX used to store number in file. In way compatible with PPPv3.
 * A data must have at least 33 bytes. */
void num_to_hex(const mpz_t num, char *data)
{
	unsigned char bin[32];
	int i;

	const int bin_len = (length-1) / 2;
	num_to_bin(num, bin, bin_len);
	for (i = 0; i < bin_len; i++)
		snprintf(data + i * 2,  3, "%02X", bin[i]);
}



void num_to_bin(const mpz_t num, unsigned char *data, const size_t length)
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
	assert(length == 16);
	memcpy(data  , &num.lo, 8);
	memcpy(data+8, &num.hi, 8);
#endif
}

/* Returns string containing number in human-readable endianness */
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
	for (i=0; str[i] && str[i+1]; i+=2) {
		for (byte=0; byte < 8; byte++) {
			*arg = num_lshift(*arg);		
		}

		if (str[i] >= '0' && str[i] <= '9')
			byte = str[i] - '0';
		else if (str[i] >= 'A' || str[i] <= 'F')
			byte = 10 + str[i] - 'A';
		else
			break;

		byte <<= 4;

		if (str[i+1] >= '0' && str[i+1] <= '9')
			byte |= str[i+1] - '0';
		else if (str[i+1] >= 'A' || str[i+1] <= 'F')
			byte |= 10 + str[i+1] - 'A';
		else
			break;

		*arg = num_add(*arg, num_i(byte));
	}

	if (str[i] || i > 32 || i < 2) {
		return 1;
	}
	return 0;
#endif
}
#endif

void num_print_hex(const mpz_t num, const unsigned int length, int msb)
{
	unsigned char bin[32];
	int i;

	const int bin_len = (length) / 2;
	num_to_bin(num, bin, bin_len);
	if (msb) {
		for (i = 0; i < bin_len; i++)
			printf("%02X", bin[i]);
	} else {
		for (i = bin_len - 1; i >= 0; i--)
			printf("%02X", bin[i]);
	}
	memset(bin, 0, sizeof(bin));
}


void num_print_dec(const num_t arg)
{
#if USE_GMP
	gmp_printf("%Zd", arg);
#else
	/* To string (Decimal) */
	char *buf = num_get_str(arg, 10);
	if (!buf) 
		printf("ERROR");
	else
		printf("%s", buf);
#endif
}







void num_testcase(void)
{
#if !USE_GMP
	const uint64_t max64 = 18446744073709551615LLU;
	const num_t max128 = num_ii(max64, max64);
	char buff[32];

	int failed = 0;
	num_t a, b, c, d;
	uint64_t r;
	int i;
	printf("*** Num testcase. Testcasing internal 128bit implementation\n");

	printf("* Shift test: ");
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

	printf("* Hex conv test: ");
	i = num_set_str(&a, "00000000000000000100000000000000", 16);
	assert(i == 0);
	if (a.hi != 1 && a.lo != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");


	num_to_hex(a, buff, 16);

	/* Twice 16327946327849612384 = e29884ad0f1eb460e29884ad0f1eb460 */
	i = num_set_str(&a, "E29884AD0f1EB460E29884AD0f1EB460", 16);
	assert(i == 0);
	      
	if (a.hi != 0xe29884ad2f1eb460ULL || a.lo != 0xe29884ad2f1eb460ULL) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	/* Should fail: */
	i = num_set_str(&a, "", 16);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_set_str(&a, "0", 16);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_set_str(&a, "G", 16);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");
	
	printf("\n");

	/* Addition */
	printf("* Addition: ");

	a = num_i(max64);
	b = num_i(1);
	c = num_add(a, b);
	if (a.hi != 0 || c.hi != 1 || c.lo != 0 || b.hi != 0 || b.lo != 1) {
		printf("FAILED "); failed++;
	} else printf("OK ");
	d = num_sub(c, b);
	if (a.lo != d.lo || a.hi != d.hi || num_cmp(a, d) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	a = max128;
	b = max128;
	c = num_sub(a, b);
	if (num_cmp_i(c, 0) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	if (num_cmp(a, b) != 0 || num_cmp(a, c) != 1 || num_cmp(c, a) != -1) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	b = num_i(max64);
	d = num_i(65784365938ULL);
	c = num_sub(a, d); 
	c = num_sub(c, b); 
	c = num_add(d, c);
	c = num_add(b, c);

	/* 340282366920938463463374607431768211455 - 18446744073709551615
	 * = 340282366920938463444927863358058659840 */
	if (num_cmp(c, a) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");


	/* Calculate high fibonacci */
	a = num_i(1);
	b = num_i(1);
	for (i=0; i<184; i++) {
		c = num_add(a, b);
		a = b;
		b = c;
	}

	/* 2^128     = 340282366920938463463374607431768211456L
	 * fibo(184) = 332825110087067562321196029789634457848 
	 * = FA63... */
	i = num_set_str(&a, "FA63C8D9FA216A8FC8A7213B333270F8", 16);
	assert(i==0);

	if (num_cmp(b, a) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");
 
	printf("\n");

	printf("* Multiplication/Division: ");

	a = num_i(50);
	r = num_div_i(&c, a, 3);
	num_print_dec(c); printf(" ");
	if (num_cmp(c, num_i(16)) != 0 && r != 2) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	printf("\nCURRENT:\n");
	i = num_set_str(&a, "010000000000000000", 16);
	assert(i==0);
	num_print_hex(a, 32, 1);
	puts("");

	a = num_i(50);
	r = num_div_i(&c, a, 3);
	num_print_dec(c); printf(" ");
	if (num_cmp(c, num_i(16)) != 0 && r != 2) {
		printf("FAILED "); failed++;
	} else printf("OK ");




	/* 0xE29884AD2F1EB460E29884AD2F1EB460 / 0xE298FFAD2F1EB460 =
	 * 18446591285620466492LLU rest = 3981894756443311584L */

	i = num_set_str(&a, "E29884AD2F1EB460E29884AD2F1EB460", 16);
	assert(i==0);

	r = num_div_i(&c, a, 0xE298FFAD2F1EB460LLU);
	num_print_dec(c); printf(" ");
	if (num_cmp(c, num_i(18446591285620466492LLU)) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	printf("Result = "); num_print_dec(c);
	printf("Rest=%" PRIu64 "\n", r);


#else

	int failed = 0;
	unsigned char num[32];
	mpz_t tmp_num;
	char *result;

	mpz_init(tmp_num);

	const int bytes = sizeof(num);
	/* All 0, but one byte */
	memset(num, 0, bytes);
	num[10] = 0xAB;

	mpz_set_d(tmp_num, 0xdeadbabe); /* Initialize with garbage */

	num_from_bin(tmp_num, num, bytes);
	result = mpz_get_str(NULL, 16, tmp_num);
	printf("num_testcase [ 0]: ");
	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		   "\x00\x00\x00\x00", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
  	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 1]: ");

	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		   "\x00\x00\x00\x00", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");


	/* 0xAA, filled with 0x80, then 0xFF  */
	memset(num, 0x80, bytes);
	num[0] = 0xAA;
	num[bytes-1] = 0xFF;

	num_from_bin(tmp_num, num, bytes);
	result = mpz_get_str(NULL, 10, tmp_num);

	printf("num_testcase [ 2]: ");
	if (strcmp(result,
		   "1155668197009629607909301529759657"
		   "36218812795816796563554883271612554597662890"
		    ) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 3]: ");

	if (memcmp(num,
		   "\xaa\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\xff", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	
	mpz_clear(tmp_num);
	return failed;

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
