#include "num.h"
#include "crypto.h"
#include "ppp.h"
#include "state.h"

const char alphabet[] =
	"!#%+23456789:=?@"
	"ABCDEFGHJKLMNPRSTUVWXYZ"
	"abcdefghijkmnopqrstuvwxyz";
const int alphabet_len = sizeof(alphabet) - 1;
const int passcode_len = 4;

/* Calculate single passcode of given number using specified key */
int ppp_get_passcode(const mpz_t key, const mpz_t counter, char *passcode, const int length)
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

/**********************
 * Passcard management
 **********************/

/* Number of passcodes in row depending on passcode length */
static int _len_to_card_size[] = {
	-1, /* use up index 0, just to make it easier */
	-1, /* minimal length is 2 */
	11, /* which fits 11 passcodes in row */
	8, 
	7,
	5, /* 5 - 6 */
	5,
	4, /* 7 */
	3, /* 8 - 10 */
	3,
	3,
	2, /* 11 - 16 */
	2,
	2,
	2,
	2,
	2,
};

static int _codes_on_card(state *s)
{
	/* is taken care elsewhere, but just to be sure */
	assert(s->code_length >= 2 && s->code_length <= 16);

	return _len_to_card_size[s->code_length];
}

/* Calculate card parameters and save them in state */
static void _calculate_card(state *s)
{
	
}


/* Calculate passcard number from passcode number */
void ppp_passcard_num_from_passcode_num(const mpz_t passcode, mpz_t passcard)
{
	
}


void whatev(state *s)
{
	/* Passcode len  passcard size: pass capacity: (*10)
	 * 2             A-K 11
	 * 3             A-H 8
	 * 4             A-G 7
	 * 5,6           A-E 5
	 * 7             A-D 4
	 * 8,9,10        A-C 3
	 * 11-16         A-B 2
	 * 
	 
	 *
	 *
	 */
}
