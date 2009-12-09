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
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int crypto_rng(unsigned char *buff, const int size, int secure)
{
	const int seed_size = 20;
	int ret;

	// ret = RAND_load_file("/etc/passwd", -1);

	if (secure) 
		ret = RAND_load_file("/dev/random", seed_size);
	else 
		ret = RAND_load_file("/dev/urandom", seed_size);

	if (ret != seed_size)
		return 1;

	assert(RAND_status() == 1);

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

