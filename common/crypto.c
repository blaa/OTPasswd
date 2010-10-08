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
#include <assert.h>

#include "crypto.h"

/* Select implementation... */
#define USE_SLOWAES 0
#define USE_POLARSSL 1
#define USE_OPENSSL 0


#define USE_SHA256_COREUTILS 1


#if USE_OPENSSL

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int crypto_ossl_rng(unsigned char *buff, const int size, int secure)
{
	const int seed_size = 20;
	int ret;

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

#endif /* USE_OPENSSL */


#if USE_SHA256_COREUTILS

#include "coreutils_sha256.h"

int crypto_sha256(const unsigned char *data, const unsigned int length, unsigned char *hash)
{
	/* In openssl implementation it seems to always succeed */
	if (sha256_buffer (data, length, hash) == NULL) {
		return 1;
	}
	return 0;
}
#endif /* USE_SHA256_COREUTILS */

#if USE_SLOWAES

#include "aes256.h"

int crypto_aes_encrypt(const unsigned char *key,
		     const unsigned char *plain,
		     unsigned char *encrypted)
{
	aes256_context ctx;

	aes256_init(&ctx, key);

	memcpy(encrypted, plain, 16);
	aes256_encrypt_ecb(&ctx, encrypted);

	aes256_done(&ctx);
	return 0;
}

int crypto_aes_decrypt(const unsigned char *key, 
		const unsigned char *encrypted,
		unsigned char *decrypted)
{
	aes256_context ctx;

	aes256_init(&ctx, key);

	memcpy(decrypted, encrypted, 16);
	aes256_decrypt_ecb(&ctx, decrypted);

	aes256_done(&ctx);
	return 0;
}

#endif /* USE_SLOWAES */

#if USE_POLARSSL

#include "polarssl_aes.h"

int crypto_aes_encrypt(const unsigned char *key,
		     const unsigned char *plain,
		     unsigned char *encrypted)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 256);


	aes_crypt_ecb(&ctx, AES_ENCRYPT, plain, encrypted);



	return 0;
}

int crypto_aes_decrypt(const unsigned char *key, 
		const unsigned char *encrypted,
		unsigned char *decrypted)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 256);

	aes_crypt_ecb(&ctx, AES_DECRYPT, encrypted, decrypted);

	return 0;
}

#endif /* USE_POLARSSL */


extern int crypto_salted_sha256(const unsigned char *data,
				const unsigned int length, 
				unsigned char *salted_hash)
{
	int ret;
	unsigned char *buf = malloc(length + 8);
	assert(data && salted_hash); /* salted_hash must be atleast 32 + 8 bytes long */

	if (!buf)
		return 1;

	/* Initialize salting buffer with 8 bytes of salt */
	if (crypto_file_rng("/dev/urandom", NULL, buf, 8) != 0) {
		ret = 2;
		goto cleanup;
	}

	/* Copy salt bytes to the resulting buffer also */
	memcpy(salted_hash, buf, 8);


	/* Copy user password to the hashing buffer just after the salt */
	memcpy(buf+8, data, length);


	/* Hash buffer; put resulting 32 bytes of data into salted_hash */
	if (crypto_sha256(buf, length+8, salted_hash + 8) != 0) {
		ret = 3;
		goto cleanup;
	}

	ret = 0;
cleanup:
	free(buf);
	return ret;
}

int crypto_verify_salted_sha256(const unsigned char *salted_hash, 
                                const unsigned char *data, const unsigned int length)
{
	int ret = 1;
	unsigned char salted_hash_new[40];
	unsigned char *buf;

	assert(salted_hash != NULL);
	assert(data != NULL);
	if (!salted_hash || !data || length == 0)
		return 1;

	buf = malloc(length + 8);

	if (!buf)
		return 1;

	/* Copy salt from salted hash to hashing buffer */
	memcpy(buf, salted_hash, 8);

	/* and to the resulting hash too */
	memcpy(salted_hash_new, buf, 8);

	/* Copy user password to the hashing buffer just after the salt */
	memcpy(buf+8, data, length);

	/* Hash buffer; put resulting 32 bytes of data into salted_hash */
	if (crypto_sha256(buf, length+8, salted_hash_new + 8) != 0) {
		ret = 3;
		goto cleanup;
	}

	if (memcmp(salted_hash_new, salted_hash, 40) == 0)
		ret = 0; /* Correct */
	else 
		ret = 1; /* Incorrect */

cleanup:
	free(buf);
	return ret;
}



int crypto_file_rng(const char *device, const char *msg, unsigned char *buf, const int count)
{
	const char spinner[] = "|/-\\"; // ".oO0Oo. ";
	const int size = strlen(spinner);
	int i;
	FILE *f;
	f= fopen(device, "r");
	if (!f) {
		return 1;
	}

	for (i=0; i<count; i++) {
		buf[i] = fgetc(f);
		if (msg && i%8 == 0) {
			printf("\r%s %3d%%  %c ", msg, i*100 / count, spinner[i/11 % size]);
			fflush(stdout);
		}
	}
	fclose(f);
	if (msg)
		printf("\r%s OK!       \n", msg);
	return 0;
}

void crypto_print_hex(const unsigned char *data, const unsigned int length)
{
	int i;
	for (i = 0; i < length; i++)
		printf("%02X", data[i]);
	printf("\n");
}


int crypto_binary_to_hex(
	const unsigned char *binary,
	const unsigned int length,
	char *hex)
{
	int i;

	assert(hex && binary);
	if (!hex || !binary)
		return 1;

	for (i = 0; i < length; i++) {
		const int tmp = binary[i];
		if (snprintf(hex + i*2, 3, "%02X", tmp) != 2) {
			return 1;
		}
	}

	return 0;
}

int crypto_hex_to_binary(const char *hex,
	const unsigned int length,
	unsigned char *binary)
{
	int i;
	char byte = 0;

	assert(hex && binary);
	assert(length % 2 == 0);
	if (!hex || !binary || length % 2 != 0)
		return 1;

	/* i:      action:
	 * 0       Read digit and shift << 4
	 * 1       Store and zero digit
	 * 2       Read and shift...
	 */
	for (i=0; i<length && hex[i]; i++) {
		if (hex[i] >= '0' && hex[i] <= '9')
			byte |= hex[i] - '0';
		else if (hex[i] >= 'A' && hex[i] <= 'F')
			byte |= 10 + hex[i] - 'A';
		else if (hex[i] >= 'a' && hex[i] <= 'f')
			byte |= 10 + hex[i] - 'a';
		else {
			return 1;
		}

		if (i % 2 == 0)
			byte <<= 4;
		else {
			binary[i / 2] = byte;
			byte = 0;
		}
	}

	if (i != length) {
		/* Length argument did not matched! */
		return 1;
	}
	
	return 0;
}
