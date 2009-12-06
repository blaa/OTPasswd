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

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

/* Get some fast pseudo random data and store in a buff
 * With secure=1 uses real random seed.
 */
extern int crypto_rng(
	unsigned char *buff,
	const int size, 
	int secure);

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

extern int crypto_testcase(void);

/* Helpers */
extern void crypto_print_hex(
	const unsigned char *data,
	const unsigned int length);


#endif
