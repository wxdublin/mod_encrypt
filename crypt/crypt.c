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
#include "chacha.h"

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
void encrypt_data_stream_(char *data, int offset, int len)
{
	int i, j, c, aes256len;
	char *keyvalue;
	char *sha0, *sha1;
	char *aes256, *twofish;
	BIGNUM *bn0, *bn1;

	// 4096 bit -> SHA256
	keyvalue = sha256(gKeyData, gKeyLen);

	// value || 0x00 -> SHA256
	keyvalue[31] |= 0x00;
	sha0 = sha256(keyvalue, 32);

	// value || 0x01 -> SHA256
	keyvalue[31] |= 0x01;
	sha1 = sha256(keyvalue, 32);

	free(keyvalue);

	// Set 256bit key of Twofish
	twofish_set_key((u4byte *)sha1, 256/8);

	// Counter0 for AES256
	bn0 = BN_new();
	BN_set_bit(bn0, 32768);
	memcpy(bn0->d, gKeyData, gKeyLen);
	//BN_set_word(bn0, 0);

	// Counter1 for AES256
	bn1 = BN_new();
	BN_set_bit(bn1, 128);
	BN_set_word(bn1, 0);

	for (i=0, c=0;; i+=32768/8) {
		// AES256 of Counter0 & 256bit key
		aes256len = 32768/8;
		aes256 = aes256_enc((unsigned char *)bn0->d, &aes256len, sha0, 256/8);

		// Twofish of Counter1 & 256bit key
		twofish = (char *)twofish_encrypt((u4byte *)bn1->d);

		for (j=0; j<32768/8; j++)
		{
			if ((i+j) == (offset+len))
				break;
			aes256[j] ^= twofish[j&0xF];
			if (((i+j) >= offset) && ((i+j) < (offset+len)))
			{
				data[c++] ^= aes256[j];
			}
		}

		BN_add_word(bn0, i);
		BN_add_word(bn1, i);

		free(aes256);
		free(twofish);

		if ((i+j) == (offset+len))
			break;
	}

	BN_free(bn0);
	BN_free(bn1);
	free(sha0);
	free(sha1);
}

 /*******************************************************************************
 * Encrypt any data by chacha20 encryption algorithm
 * csc : cancel special charactor (0-no cancle, 1-encrypt, 2-decrypt)
 */
void encrypt_data_stream(char *data, int offset, int len, int csc)
{
	int i;
	char *buff;

	// check parameters
	if (!data || ((offset+len) <= 0))
		return;

	// alloc memory
	buff = malloc(offset+len);

	memcpy(&buff[offset], data, len);

	if (csc == 0) {			// encrypt/decrypt without cancel special character
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyData, &gKeyData[256], (size_t)0);
		memcpy(data, &buff[offset], len);
	} 
	else					// encrypt with cancel special character
	{
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyData, &gKeyData[256], (size_t)0);
		for (i=offset; i<(offset+len); i++) 
		{
			if ((buff[i] == '\r') || (buff[i] == '\n') || (buff[i] == '\0') || 
				(buff[i] == '\v') || (buff[i] == '\f'))	{
					data[i-offset] += 0x70;
			}
		}
		memcpy(&buff[offset], data, len);
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyData, &gKeyData[256], (size_t)0);
		memcpy(data, &buff[offset], len);
	}

	free(buff);

	return;
}

void decrypt_data_stream(char *data, int offset, int len, int csc)
{
	int i;
	char *buff;

	// check parameters
	if (!data || ((offset+len) <= 0))
		return;

	// alloc memory
	buff = malloc(offset+len);

	memcpy(&buff[offset], data, len);

	if (csc == 0) {			// encrypt/decrypt without cancel special character
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyData, &gKeyData[256], (size_t)0);
		memcpy(data, &buff[offset], len);
	} 
	else					// decrypt with cancel special character
	{
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyData, &gKeyData[256], (size_t)0);
		memcpy(data, &buff[offset], len);
		for (i=0; i<len; i++) 
		{
			unsigned char ch = data[i];
			if (ch > (unsigned char)0x8F)
			{
				ch -= (unsigned char)0x70;
				data[i] = ch;
			}
		}
	}

	free(buff);

	return;
}