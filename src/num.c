/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
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

#include "num.h"

int num_testcase(void)
{
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
}


