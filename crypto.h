#ifndef _CRYPTO_H_
#define _CRYPTO_H_

extern int crypto_rng(
	unsigned char *buff,
	const int size, 
	int secure);

extern int crypto_aes_encrypt(
	const unsigned char *key,
	const unsigned char *plain,
	unsigned char *encrypted);

extern int crypto_aes_decrypt(
	const unsigned char *key,
	const unsigned char *encrypted,
	unsigned char *decrypted);

extern int crypto_sha256(
	const unsigned char *data,
	const unsigned int length,
	unsigned char *hash);

extern void crypto_testcase(void);

/* Helpers */
extern void crypto_print_hex(
	const unsigned char *data,
	const unsigned int length);


#endif
