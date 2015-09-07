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

#include "fcgi.h"
#include "aes256ctr.h"
#include "aes256cbc.h"
#include "crypt.h"
#include "key.h"

//////////////////////////////////////////////////////////////////////////

void *InitEncrypt(request_rec * r, fcgi_request * fr)
{
	if (fr->encryptor.dataKeyLength == 0)
	{
		// key authorization
		if (key_auth_request(r, &fr->encryptor, fr->fs->master_key_server) < 0)
			return NULL;

		// get master key
		if (key_master_request(r, &fr->encryptor, fr->fs->master_key_server) < 0)
			return NULL;

		// get data key
		if (key_data_request(r, &fr->encryptor, fr->fs->data_key_server) < 0)
			return NULL;
	}
	
	return (void *)InitAesCtr(fr->encryptor.dataKey, fr->encryptor.dataKeyLength);
}

void *InitDecrypt(request_rec * r, fcgi_request * fr)
{
	if (fr->decryptor.dataKeyLength == 0)
	{
		// key authorization
		if (key_auth_request(r, &fr->decryptor, fr->fs->master_key_server) < 0)
			return NULL;

		// get master key
		if (key_master_request(r, &fr->decryptor, fr->fs->master_key_server) < 0)
			return NULL;

		// get data key
		if (key_data_request(r, &fr->decryptor, fr->fs->data_key_server) < 0)
			return NULL;
	}

	return (void *)InitAesCtr(fr->decryptor.dataKey, fr->decryptor.dataKeyLength);
}

void CloseCrypt(void *ctx)
{
	if (!ctx)
		return;
	
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
	if (!ctx || !data || ((offset+len) <= 0))
		return;

	buff = malloc(BUFF_SIZE);
	memset(buff, 0, BUFF_SIZE);

	block_cnt = offset/BUFF_SIZE;
	block_offset = 0;
	block_size = BUFF_SIZE*block_cnt;
	for (i=0; i<block_cnt; i++)
		CryptAesCtr((EVP_CIPHER_CTX *)ctx, buff, BUFF_SIZE, buff);
	
	block_cnt = 1;
	block_offset = offset%BUFF_SIZE;
	block_size = min(len, BUFF_SIZE-block_offset);
	memset(buff, 0, BUFF_SIZE);
	memcpy(&buff[block_offset], data, block_size);
	CryptAesCtr((EVP_CIPHER_CTX *)ctx, buff, BUFF_SIZE, buff);
	memcpy(data, &buff[block_offset], block_size);

	block_offset = block_size;
	block_size = len - block_offset;
	if (block_size > 0)
		CryptAesCtr((EVP_CIPHER_CTX *)ctx, &data[block_offset], block_size, &data[block_offset]);
	
	free(buff);

	return;
}

