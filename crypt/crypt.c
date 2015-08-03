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

#include "aes256/aes256.h"
#include "sha256/sha256.h"
#include "twofish/twofish.h"
#include "chacha/chacha.h"
#include "crypt.h"

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
void encrypt_data_stream_(char *data, int offset, int len)
{
	int i, j, c, aes256len;
	char *keyvalue;
	char *sha0, *sha1;
	char *aes256, *twofish;
	BIGNUM *bn0, *bn1;
	EVP_CIPHER_CTX *ctx;

	// Init AES CTR 256
	ctx = InitCrypt();

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

	aes256len = 32768/8;
	aes256 = malloc(aes256len);
	for (i=0, c=0;; i+=32768/8) {
		// AES256 of Counter0 & 256bit key
		EncryptAesCtr(ctx, (unsigned char *)bn0->d, aes256len, aes256, sha0, 256/8);

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

		free(twofish);

		if ((i+j) == (offset+len))
			break;
	}
	free(aes256);

	BN_free(bn0);
	BN_free(bn1);
	free(sha0);
	free(sha1);

	CloseCrypt(ctx);
}
//////////////////////////////////////////////////////////////////////////
static unsigned char gKeyString[] = "The light touches is our kingdom";
static size_t gKeyLength = 32;

static unsigned char gIvString[] = "Love you";
static size_t gIvLength = 8;

 /*******************************************************************************
 * Encrypt any data by chacha20 encryption algorithm
 * csc : cancel special charactor (0-no cancle, 1-encrypt, 2-decrypt)
 */
void encrypt_data_stream__(char *data, int offset, int len, int csc)
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
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyString, gIvString, (size_t)0);
		memcpy(data, &buff[offset], len);
	} 
	else					// encrypt with cancel special character
	{
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyString, gIvString, (size_t)0);
		for (i=offset; i<(offset+len); i++) 
		{
			if ((buff[i] == '\r') || (buff[i] == '\n') || (buff[i] == '\0') || 
				(buff[i] == '\v') || (buff[i] == '\f'))	{
					data[i-offset] += 0x70;
			}
		}
		memcpy(&buff[offset], data, len);
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyString, gIvString, (size_t)0);
		memcpy(data, &buff[offset], len);
	}

	free(buff);

	return;
}

void decrypt_data_stream__(char *data, int offset, int len, int csc)
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
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyString, gIvString, (size_t)0);
		memcpy(data, &buff[offset], len);
	} 
	else					// decrypt with cancel special character
	{
		CRYPTO_chacha_20(buff, buff, offset+len, gKeyString, gIvString, (size_t)0);
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

void *InitCrypt(void)
{
	return (void *)InitAesCtr(gKeyData, gKeyLen);
}

void CloseCrypt(void *ctx)
{
	UninitAesCtr((EVP_CIPHER_CTX *)ctx);
}

#define BUFF_SIZE	1024

 /*******************************************************************************
 * Encrypt any data by AES ctr encryption algorithm
 */
void CryptDataStream(void *ctx, char *data, int offset, int len)
{
	int i;
	int block_cnt, block_offset, block_size;
	char *buff;

	// check parameters
	if (!data || ((offset+len) <= 0))
		return;

	buff = malloc(BUFF_SIZE);
	memset(buff, 0, BUFF_SIZE);

	block_cnt = offset/BUFF_SIZE;
	block_offset = 0;
	block_size = BUFF_SIZE*block_cnt;
	for (i=0; i<block_cnt; i++)
		EncryptAesCtr((EVP_CIPHER_CTX *)ctx, buff, BUFF_SIZE, buff, gKeyData, gKeyLen);
	
	block_cnt = 1;
	block_offset = offset%BUFF_SIZE;
	block_size = min(len, BUFF_SIZE-block_offset);
	memset(buff, 0, BUFF_SIZE);
	memcpy(&buff[block_offset], data, block_size);
	EncryptAesCtr((EVP_CIPHER_CTX *)ctx, buff, BUFF_SIZE, buff, gKeyData, gKeyLen);
	memcpy(data, &buff[block_offset], block_size);

	block_offset = block_size;
	block_size = len - block_offset;
	if (block_size > 0)
		EncryptAesCtr((EVP_CIPHER_CTX *)ctx, &data[block_offset], block_size, &data[block_offset], gKeyData, gKeyLen);
	
	free(buff);

	return;
}

