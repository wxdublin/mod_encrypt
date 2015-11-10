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
static unsigned char gTestKeyData[] = \
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"\
"yzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"\
"wxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"\
"uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"\
"stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"\
"qrstuv";
static int gTestKeyLen = 256;

int InitEncrypt(fcgi_crypt * encryptor)
{
	if (!fcgi_authserver || !fcgi_masterkeyserver || !fcgi_datakeyserver)
	{
		// only for testing without key servers
		memcpy(encryptor->dataKey, gTestKeyData, gTestKeyLen);
		encryptor->dataKeyLength = gTestKeyLen;
	} 
	else
	{
		// get encrypt key from memcache or auth key server
		if (encryptor->dataKeyLength == 0)
		{
			// get active key
			if (key_active_request(encryptor) < 0)
				return -1;
		}
	}
	
	// Initialize encrypt module
	encryptor->crypt = InitAesCtr((unsigned char *)encryptor->dataKey, encryptor->dataKeyLength);
	if (encryptor->crypt == NULL)
	{
		return -1;
	}
	
	return 0;
}

int InitDecrypt(fcgi_crypt * decryptor)
{
	if (!fcgi_authserver || !fcgi_masterkeyserver || !fcgi_datakeyserver)
	{
		// only for testing without key servers
		memcpy(decryptor->dataKey, gTestKeyData, gTestKeyLen);
		decryptor->dataKeyLength = gTestKeyLen;
	}
	else
	{
		// get decrypt key from memcache or auth key server
		if (decryptor->dataKeyLength == 0)
		{
			// get active key
			if (key_old_request(decryptor) < 0)
				return -1;
		}
	}
	
	// Initialize encrypt module
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
	EVP_CIPHER_CTX *ctx;
	unsigned char buff[BUF_SIZE];

	// check parameters
	if (!cryptor || !cryptor->crypt || !data || ((offset+len) <= 0))
		return;
	
	ctx = (EVP_CIPHER_CTX *)cryptor->crypt;
	while (offset > BUF_SIZE)
	{
		memset(buff, 0, BUF_SIZE);
		CryptAesCtr(ctx, buff, BUF_SIZE, buff);
		offset -= BUF_SIZE;
	}
	if (offset > 0)
	{
		CryptAesCtr(ctx, buff, offset, buff);
	}

	CryptAesCtr(ctx, (unsigned char*)data, len, (unsigned char*)data);

	return;
}

