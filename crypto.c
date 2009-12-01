/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * (C) 2009 by Tomasz bla Fortuna <bla@thera.be>, <bla@af.gliwice.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * See LICENSE file for details.
 **********************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int crypto_rng(unsigned char *buff, const int size, int secure)
{
	const int seed_size = 20;
	int ret;

	if (secure) 
		ret = RAND_load_file("/dev/random", seed_size);
	else 
		ret = RAND_load_file("/dev/urandom", seed_size);

	if (ret != seed_size)
		return 1;

	if (RAND_bytes(buff, size) != 1) {
		RAND_cleanup();
		return 1;
	}

	RAND_cleanup();
	return 0;
}

int crypto_aes_encrypt(const unsigned char *key,
		     const unsigned char *plain,
		     unsigned char *encrypted)
{
	int ret;
	int written = 0;
	EVP_CIPHER_CTX ctx;

	/* Paranoid check */
	assert(EVP_MAX_KEY_LENGTH == 32);

	ret = EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, NULL);
	if (ret != 1)
		return 1;

	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	ret = EVP_EncryptUpdate(&ctx, encrypted, &written, plain, 128/8);
	if (ret != 1) {
		ret = 1;
		goto cleanup;
	}
	
	if (written != 128/8) {
		ret = 1;
		goto cleanup;
	} else {
		ret = 0;
	}

cleanup:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1)
		return 1;
	return ret;
}

int crypto_aes_decrypt(const unsigned char *key, 
		const unsigned char *encrypted,
		unsigned char *decrypted)
{
	int ret;
	EVP_CIPHER_CTX ctx;
	int written = 128/8;

	ret = EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, NULL);
	if (ret != 1)
		return 1;

	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	ret = EVP_DecryptUpdate(&ctx, decrypted, &written, encrypted, 16);
	if (ret != 1) {
		ret = 1;
		goto cleanup;
	}
		
	if (written != 128/8) {
		ret = 1;
		goto cleanup;
	} else {
		ret = 0;
	}

cleanup:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1)
		return 1;
	return ret;
}

int crypto_sha256(const unsigned char *data, const unsigned int length, unsigned char *hash)
{
	SHA256(data, length, hash);

	/* In openssl implementation it seems to always succeed */
	return 0;
}

void crypto_print_hex(const unsigned char *data, const unsigned int length)
{
	int i;
	for (i = 0; i < length; i++)
		printf("%02X", data[i]);
	printf("\n");
}

void crypto_testcase(void)
{
	int i;

	unsigned char plain[] = 
		"To be encrypted.";
	unsigned char encrypted_origin[] = 
		"\x4e\xb9\x42\x33\xa2\xcf\x6c\x3c"
		"\x5f\x96\xf1\x11\x57\x8a\xa7\x78";

	unsigned char encrypted[16], decrypted[17];
	unsigned char key[32] = "This is the key";

	crypto_aes_encrypt(key, plain, encrypted);
	crypto_aes_decrypt(key, encrypted, decrypted);

	printf("crypto_aes_test [ 1]: ");
	if (memcmp(plain, decrypted, 16) != 0) {
		printf("FAILED ");
	} else {
		printf("PASSED ");		
	}

	if (memcmp(encrypted, encrypted_origin, 16) != 0) {
		printf("FAILED\n");
	} else {
		printf("PASSED\n");		
	}

	printf("crypto_aes_test [%2d]: ", i+1);
	for (i = 0; i < 10; i++) {
		crypto_rng(plain, 16, 0);
		crypto_aes_encrypt(key, plain, encrypted);
		crypto_aes_decrypt(key, encrypted, decrypted);
		

		if (memcmp(plain, decrypted, 16) != 0) {
			printf("FAILED ");
		} else {
			printf("PASSED ");		
		}
	}
	printf("\n");

	/* SHA256 testcase */
	const unsigned char hash_plain[] = "To be encrypted.";
	unsigned char hash[32];
	const unsigned char hash_origin[32] = 
		"\x4f\xee\xfa\x18\x7b\x71\xc8\xf1\x36\xb6\xdb\xc8\x6e"
		"\xa6\x4f\x72\x1f\xfa\xa6\x0c\x52\x34\x96\x45\xeb\x87"
		"\x82\x56\x8e\x72\x17\xe1";

	crypto_sha256(hash_plain, strlen((char *) hash_plain), hash);
	printf("sha_test [ 1]: ");
	if (memcmp(hash, hash_origin, 32) != 0) {
		printf("FAILED\n");
	} else {
		printf("PASSED\n");		
	}
}
