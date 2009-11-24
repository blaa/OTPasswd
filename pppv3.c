#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include <assert.h>

#include "crypto.h"
#include "num.h"

/* State */
typedef struct {
	mpz_t counter; /* 128 bit counter */
	mpz_t sequence_key;
} state;

const char alphabet[] =
	"!#%+23456789:=?@"
	"ABCDEFGHJKLMNPRSTUVWXYZ"
	"abcdefghijkmnopqrstuvwxyz";
const int alphabet_len = sizeof(alphabet) - 1;
const int passcode_len = 4;


void state_init(state *s)
{
	mpz_init(s->counter);
	mpz_set_d(s->counter, 1);

	unsigned char tmp[32] = {0x00};
	tmp[3] = 0xAB;
//	assert( crypto_rng(tmp, 32, 0) == 0 ); /* TODO: Change to secure */

	mpz_init(s->sequence_key);
	num_from_bin(s->sequence_key, tmp, 32);

}

void state_debug(state *s)
{
	printf("Sequence key: ");
	num_print(s->sequence_key, 16);
	printf("Counter: ");
	num_print(s->counter, 16);
}

/* Calculate single passcode of given number using specified key */
int get_passcode(const mpz_t key, const mpz_t counter, char *passcode, const int length)
{
	unsigned char key_bin[32];
	unsigned char cnt_bin[16];
	unsigned char cipher_bin[16];
	mpz_t cipher;
	mpz_t quotient; 
	int i;

	int ret;

	/* Check for illegal length */
	if (length < 2 || length > 16)
		return 1;

	if (!passcode)
		return 2;

	mpz_init(quotient);
	mpz_init(cipher);

	/* Convert numbers to binary */
	num_to_bin(key, key_bin, 32);
	num_to_bin(counter, cnt_bin, 16);

	/* Encrypt counter with key */
	ret = crypto_aes_encrypt(key_bin, cnt_bin, cipher_bin);
	if (ret != 0) {
		goto clear;
	}

	/* Convert result back to number */
	num_from_bin(cipher, cipher_bin, 16);

/*	printf("seqkey: "); crypto_print_hex(key_bin, 32);
	printf("cnt   : "); crypto_print_hex(cnt_bin, 16);
	printf("cipher: "); crypto_print_hex(cipher_bin, 16);
*/

	for (i=0; i<length; i++) {
		unsigned long int r = mpz_fdiv_q_ui(quotient, cipher, alphabet_len);
		mpz_set(cipher, quotient);

		passcode[i] = alphabet[r];
	}

clear:
	memset(key_bin, 0, sizeof(key_bin));
	memset(cnt_bin, 0, sizeof(cnt_bin));
	memset(cipher_bin, 0, sizeof(cipher_bin));

	num_dispose(quotient);
	num_dispose(cipher);
	return ret;
}

int main(int argc, char **argv)
{
	state s;
	state_init(&s);

	printf("alphabet_len = %u\n", alphabet_len);

	state_debug(&s);

	char passcode[6] = {0};
	get_passcode(s.sequence_key, s.counter, passcode, 4);
	printf("passcode: %s\n", passcode);

	num_testcase();
	crypto_testcase();
	return 0;
}
