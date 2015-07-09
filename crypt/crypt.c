/**
  encryption/decryption api used in mod_encrypt

  Baze Ilijoskki (bazeilijoskki@gmail.com)
**/

#ifdef APACHE2
#include "apr_lib.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>

#include "sha256.h"
#include "aes256.h"
#include "twofish.h"

static unsigned char gKeyData[] = \
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr";
static int gKeyLen = 512;

 /*******************************************************************************
 * Encrypt any data by crypt key
 */
char *encrypt_data(char *data, int *len)
{
	return aes256_enc(data, len, gKeyData, gKeyLen);
}

 /*******************************************************************************
 * Decryt any data by crypt key
 */
char *decrypt_data(char *data, int *len)
{
	return aes256_dec(data, len, gKeyData, gKeyLen);
}

 /*******************************************************************************
 * Encrypt any data by crypt key
 */
void encrypt_data_stream(char *data, int len)
{
	int i, j, aes256len;
	char *keyvalue;
	char *sha0, *sha1;
	char *aes256, *twofish;
	BIGNUM *bn;

	keyvalue = sha256(gKeyData, gKeyLen);

	keyvalue[31] |= 0x00;
	sha0 = sha256(keyvalue, 32);

	keyvalue[31] |= 0x01;
	sha1 = sha256(keyvalue, 32);

	free(keyvalue);

	bn = BN_new();
	BN_set_bit(bn, 128);
	BN_set_word(bn, 0);

	twofish_set_key((u4byte *)sha1, 256/8);

	for (i=0;; i+=128/8) {
		BN_add_word(bn, 1);

		aes256len = 128/8;
		aes256 = aes256_enc((unsigned char *)bn->d, &aes256len, sha0, 256/8);
		twofish = (char *)twofish_encrypt((u4byte *)bn->d);

		for (j=0; j<128/8; j++)
		{
			aes256[j] ^= twofish[j];
			data[i+j] ^= aes256[j];

			if ((i+j) == len)
				break;
		}

		free(aes256);
		free(twofish);

		if ((i+j) == len)
			break;
	}

	BN_free(bn);
	free(sha0);
	free(sha1);
}
