#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "num.h"

void num_testcase(void)
{
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
		   "\x00\x00\x00\x00", 32) != 0) 
		printf("FAILED\n");
	else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
  	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 1]: ");

	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		   "\x00\x00\x00\x00", 32) != 0) 
		printf("FAILED\n");
	else
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
		   ) != 0)
		printf("FAILED\n");
	else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 3]: ");

	if (memcmp(num,
		   "\xaa\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\xff", 32) != 0) 
		printf("FAILED\n");
	else
		printf("PASSED\n");
	
	mpz_clear(tmp_num);
}


