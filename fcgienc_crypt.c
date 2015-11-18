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

#include "fcgienc.h"
#include "fcgienc_aes256ctr.h"
#include "fcgienc_aes256cbc.h"
#include "fcgienc_crypt.h"
#include "fcgienc_key.h"

////////////////////////////////////////////////////////////////////////// 

int InitEncrypt(fcgienc_crypt * encryptor)
{
	if (!fcgienc_authserver || !fcgienc_masterkeyserver || !fcgienc_datakeyserver)
	{
		if (fcgienc_cryptkeystring)
		{
			// only for testing without key servers
			encryptor->dataKeyLength = strlen(fcgienc_cryptkeystring);
			if (encryptor->dataKeyLength > 256)
				encryptor->dataKeyLength = 256;
			
			memcpy(encryptor->dataKey, fcgienc_cryptkeystring, encryptor->dataKeyLength);
		}
		else
		{
			return -1;
		}
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

int InitDecrypt(fcgienc_crypt * decryptor)
{
	if (!fcgienc_authserver || !fcgienc_masterkeyserver || !fcgienc_datakeyserver)
	{
		if (fcgienc_cryptkeystring)
		{
			// only for testing without key servers
			decryptor->dataKeyLength = strlen(fcgienc_cryptkeystring);
			if (decryptor->dataKeyLength > 256)
				decryptor->dataKeyLength = 256;

			memcpy(decryptor->dataKey, fcgienc_cryptkeystring, decryptor->dataKeyLength);
		}
		else
		{
			return -1;
		}
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

void CloseCrypt(fcgienc_crypt * cryptor)
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

void CryptDataStream(fcgienc_crypt * cryptor, char *data, int offset, int len)
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

