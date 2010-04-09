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
 *   Unified interface to SHA256, AES256 and some RNG
 **********************************************************************/

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

/* Get some fast cryptographically-secure pseudo-random data
 * and store in a buff. With secure=1 uses real random seed.
 */
/*
extern int crypto_ossl_rng(
	unsigned char *buff,
	const int size, 
	int secure);
*/

/* Read count of random data from device (urandom or random usually)
 * into buf. Print message before you start and show progress
 */
extern int crypto_file_rng(
	const char *device, 
	const char *msg, 
	unsigned char *buf, 
	const int count);


/* Encrypt 128 bits with 256 bit key */
extern int crypto_aes_encrypt(
	const unsigned char *key,
	const unsigned char *plain,
	unsigned char *encrypted);

/* Decrypt 128 bits with 256 bit key */

extern int crypto_aes_decrypt(
	const unsigned char *key,
	const unsigned char *encrypted,
	unsigned char *decrypted);

/* Calculate 256bit long hash of data */
extern int crypto_sha256(
	const unsigned char *data,
	const unsigned int length,
	unsigned char *hash);

/* Helpers */

/* Calculate 256bit long hash of data with 8 bytes of random salt
 * Salt is placed at the beginning of salted_hash, therefore salted_hash
 * must be atleast 32+8 bytes long = 40.
 */
extern int crypto_salted_sha256(
	const unsigned char *data,
	const unsigned int length,
	unsigned char *salted_hash);

extern int crypto_verify_salted_sha256(
	const unsigned char *salted_hash, 
	const unsigned char *data,
	const unsigned int length);

/* Display hexadecimally binary data */
extern void crypto_print_hex(
	const unsigned char *data,
	const unsigned int length);

/* Stores binary data inside 'output' text memory
 * as hexadecimally encoded string 
 * length*2 + 1 bytes will be written
 * */
extern int crypto_binary_to_hex(
	const unsigned char *binary,
	const unsigned int length,
	char *hex);

extern int crypto_hex_to_binary(
	const char *hex,
	const unsigned int length,
	unsigned char *binary);


#endif
