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
#if !USE_GMP
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
	*arg = num_i(0);

	switch (base) {
	case 10:
	{
		for (i=0; str[i]; i++) {
			/* Shift */
			*arg = num_mul_i(*arg, 10);

			if (str[i] < '0' || str[i] > '9')
				return 1;

			*arg = num_add(*arg, num_i(str[i] - '0'));
		}
		if (str[i]) 
			return 1;
		return 0;
	}
	case 16:
		for (i=0; str[i]; i++) {
			/* Shift */
			for (byte=0; byte < 4; byte++) {
				*arg = num_lshift(*arg);		
			}
			
			if (str[i] >= '0' && str[i] <= '9')
				byte = str[i] - '0';
			else if (str[i] >= 'A' && str[i] <= 'F')
				byte = 10 + str[i] - 'A';
			else
				return 1;
			
			*arg = num_add(*arg, num_i(byte));
		}

		if (str[i] || i > 32 || i < 2) {
			return 1;
		}

		return 0;
	default:
		return 1;
	}
}
#endif

int num_export(const num_t num, char *buff, enum num_str_type t) 
{
	int ret;
#if USE_GMP
	size_t size = 1;

	switch (t) {
	case NUM_FORMAT_DEC:
	{
		char *tmp = mpz_get_str(buff, 10, arg);
		assert(tmp);
		if (!tmp) 
			return 1;
		return 0;
	}

	case NUM_FORMAT_HEX:
	{
		char *tmp = mpz_get_str(buff, 16, arg);
		assert(tmp);
		if (!tmp) 
			return 1;
		return 0;
	}

	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		/* Handle 0 numbers; otherwise nothing would be written to data */
		if (mpz_cmp_si(num, 0) == 0)
			memset(data, 0, length);
		else 
			(void) mpz_export(data, &size, 1, length, -1, 0, num);
		assert(size == 1);

		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return 1;
	}

#else
/* static inline int _num_get_str(const num_t arg, char *buff, const int base)
 */

	switch (t) {
	case NUM_FORMAT_DEC:
		ret = _num_get_str(num, buff, 10);
		return ret;

	case NUM_FORMAT_PPP_HEX:
	{
		char bin[16];
		int i;
		num_export(num, bin, NUM_FORMAT_BIN);
		for (i = 0; i < 16; i++)
			snprintf(buff + i * 2,  3, "%02X", bin[i]);
		
		return 0;
	}

	case NUM_FORMAT_HEX:
	{
		char bin[16];
		int i;
		num_export(num, bin, NUM_FORMAT_BIN);
		for (i = 0; i < 16; i++)
			snprintf(buff + i * 2,  3, "%02X", bin[15 - i]);
		
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
#endif
	return 1;
}

/* 
 * Parse either decimal or hex into a num_t type.
 * 0 - success
 */
int num_import(num_t *num, const char *buff, enum num_str_type t)
{
	int ret;
#if USE_GMP
	switch (t) {
	case NUM_FORMAT_DEC:
		ret = gmp_sscanf(str, "%Zu", *arg);
		return ret;

	case NUM_FORMAT_HEX:
	{
		printf("Unimplemented!\n");
		/* ret = gmp_sscanf(str, "%ZX", *arg); */
		assert(0);
		return 1;
	}

	case NUM_FORMAT_PPP_HEX:
		break;
	case NUM_FORMAT_BIN:
		mpz_import(num, 1, 1, length, -1 /* LSB to match ppp behaviour */ , 0, data);
		return 0;

	default:
		/* Incorrect input */
		assert(0); 
		return 1;
	}

#else
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
#endif
	return 1;
}


/*****************************
 * Printing helpers 
 *****************************/
void num_print_hex(const num_t num, const unsigned int length, int msb)
{
	char hex[35];
	int i;

	if (msb) {
		i = num_export(num, hex, NUM_FORMAT_HEX);
	} else {
		i = num_export(num, hex, NUM_FORMAT_PPP_HEX);		
	}

	assert(i==0);
	if (i != 0)
		return;

	printf("%s", hex);
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




void num_testcase(void)
{
#if !USE_GMP
	const uint64_t max64 = 18446744073709551615LLU;
	const num_t max128 = num_ii(max64, max64);
	char buff[42];

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
		printf("FAILED\n");
	} else 
		printf("OK\n");

	printf("* Hex conv test: ");
	i = num_import(&a, "00000000000000010000000000000023", NUM_FORMAT_HEX);
	assert(i == 0);
	if (a.hi != 1 && a.lo != 0x23) {
		printf("FAILED_IMP1 "); failed++;
	} else printf("OK ");

	/* Twice 16327946327849612384 = e29884ad0f1eb460e29884ad0f1eb460 */
	i = num_import(&a, "E29884AD0F1EB460E29884AD0F1EB460", NUM_FORMAT_HEX);
	assert(i == 0);
	if (a.hi != 0xE29884AD0F1EB460 || a.lo != 0xE29884AD0F1EB460ULL) {
		printf("FAILED_IMP2 "); failed++;
	} else printf("OK ");


	/* Exports: bin, hex, ppp_hex, dec */
	i = num_import(&a, "112233445566778899AABBCCDDEEFF00", NUM_FORMAT_HEX);
	assert(i == 0);
	i = num_export(a, buff, NUM_FORMAT_BIN);
	if (memcmp(buff,   "\x00\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11", 16) != 0) {
		printf("FAILED_BIN "); failed++;
	} else printf("OK ");

	i = num_export(a, buff, NUM_FORMAT_HEX);
	assert(i==0);
	if (strcmp(buff, "11223344556677FFFFFFFFFFFFFFFF00") != 0) {
		printf("FAILED_HEX "); failed++;
	} else printf("OK ");

	i = num_export(a, buff, NUM_FORMAT_PPP_HEX); 
	assert(i==0);
	if (strcmp(buff, "00FFFFFFFFFFFFFFFF77665544332211") != 0) {
		printf("FAILED_HEX "); failed++;
	} else printf("OK ");

	i = num_export(a, buff, NUM_FORMAT_DEC); 
	assert(i==0);
	if (strcmp(buff, "22774453838368691933757882222884355840") != 0) {
		printf("FAILED_DEC "); failed++;
	} else printf("OK ");

	i = num_import(&b, "22774453838368691933757882222884355840", NUM_FORMAT_DEC);
	assert(i==0);
	if (num_cmp(a, b) != 0) {
		printf("FAILED_DEC_IMP "); failed++;
	} else printf("OK ");


	/* Should "fail": */
	i = num_import(&a, "", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_import(&a, "0", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_import(&a, "FG", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED"); failed++;
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
	i = num_import(&a, "FA63C8D9FA216A8FC8A7213B333270F8", NUM_FORMAT_HEX);
	assert(i==0);

	if (num_cmp(b, a) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");
 
	printf("\n");

	printf("* Multiplication/Division: ");

	a = num_i(18446744073709551615ULL);
	r = num_div_i(&c, a, 7);
	if (num_cmp(c, num_i(2635249153387078802)) != 0 && r != 1) {
		printf("FAILED "); failed++;
	} else printf("OK ");


	printf("\nCURRENT:\n");
	i = num_import(&a, "010000000000000000", NUM_FORMAT_HEX);
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

//	i = num_set_str(&a, "E29884AD2F1EB460E29884AD2F1EB460", 16);
	i = num_import(&a, "E29884AD2F1EB460E29884AD2F1EB460", NUM_FORMAT_HEX);
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
