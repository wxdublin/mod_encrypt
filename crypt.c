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

int InitEncrypt(fcgi_crypt * encryptor)
{
	if (encryptor->dataKeyLength == 0)
	{
// 		encryptor->dataKeyLength = 15;
// 		strcpy(encryptor->dataKey, "deadbeef0123456");
// 		encryptor->dataKey[15] = 0;
// 		strcpy(encryptor->masterKeyId, "5e0e9463-acc2-45c7-91a4-ce730f68842b");
// 		strcpy(encryptor->dataKeyId, "2bae2abd-2615-47d9-a508-fe1b7a417ccd");

		// get active key
 		if (key_active_request(encryptor) < 0)
 			return -1;
	}
	
	encryptor->crypt = InitAesCtr((unsigned char *)encryptor->dataKey, encryptor->dataKeyLength);

	if (encryptor->crypt == NULL)
	{
		return -1;
	}
	
	return 0;
}

int InitDecrypt(fcgi_crypt * decryptor)
{
	if (decryptor->dataKeyLength == 0)
	{
// 		decryptor->dataKeyLength = 15;
// 		strcpy(decryptor->dataKey, "deadbeef0123456");
// 		decryptor->dataKey[15] = 0;

		// get active key
 		if (key_old_request(decryptor) < 0)
 			return -1;
	}

	decryptor->crypt = InitAesCtr((unsigned char *)decryptor->dataKey, decryptor->dataKeyLength);

	if (decryptor->crypt == NULL)
	{
		return -1;
	}

	return 0;
}

void CloseCrypt(fcgi_crypt * cryptor)
{
	if (!cryptor || !cryptor->crypt)
	{
		return;
	}
	
	UninitAesCtr((EVP_CIPHER_CTX *)cryptor->crypt);
}

/*******************************************************************************
 * Encrypt any data by AES ctr encryption algorithm
 */
void CryptDataStream(fcgi_crypt * cryptor, char *data, int offset, int len)
{
	int i;
	int block_cnt, block_offset, block_size;
	unsigned char *buff;
	EVP_CIPHER_CTX *ctx;

	// check parameters
	if (!cryptor || !data || ((offset+len) <= 0))
		return;

	ctx = (EVP_CIPHER_CTX *)cryptor->crypt;

	buff = malloc(BUF_SIZE);
	memset(buff, 0, BUF_SIZE);

	block_cnt = offset/BUF_SIZE;
	block_offset = 0;
	block_size = BUF_SIZE*block_cnt;
	for (i=0; i<block_cnt; i++)
		CryptAesCtr(ctx, buff, BUF_SIZE, buff);
	
	block_cnt = 1;
	block_offset = offset%BUF_SIZE;
	block_size = min(len, BUF_SIZE-block_offset);
	memset(buff, 0, BUF_SIZE);
	memcpy(&buff[block_offset], data, block_size);
	CryptAesCtr(ctx, buff, BUF_SIZE, buff);
	memcpy(data, &buff[block_offset], block_size);

	block_offset = block_size;
	block_size = len - block_offset;
	if (block_size > 0)
		CryptAesCtr(ctx, (unsigned char *)&data[block_offset], block_size, (unsigned char *)&data[block_offset]);
	
	free(buff);

	return;
}

