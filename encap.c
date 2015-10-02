/**
  encapsulation/decapsulation api used in mod_encrypt

  Baze Ilijoskki (bazeilijoskki@gmail.com)
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"

//////////////////////////////////////////////////////////////////////////

/*
capsulation structure :
Header - 20bytes
size of masterKeyId string - 2bytes
masterKeyId string
size of dataKeyId string - 2bytes
dataKeyId string
size of usermd metadata - 2bytes
usermd metadata string
Tail - 20bytes
*/

#define CAP_HEADER_STRING "aj2003JuZLu67OwDSuUM"
#define CAP_TAIL_STRING "Usqx2li3Z42tbQQKuK17"

//////////////////////////////////////////////////////////////////////////

int encap_metadata(char *encapStr, int encapLen, 
				   const char *masterKeyId, int masterKeyLen, 
				   const char *dataKeyId, int dataKeyLen, 
				   const char *usermdStr, int usermdLen)
{
	int ret;
	int keylen;
	char *plaintxt;
	char *ptr;

	// check input parameter
	if (!encapStr)
		return -1;

	// calculate buffer size
	keylen = 20 + 2 + masterKeyLen + 2 + dataKeyLen + 2 + usermdLen + 20;
	plaintxt = malloc(keylen+1);
	if (!plaintxt)
		goto ENCAP_FAILED;

	ptr = &plaintxt[0];

	// add header (offset = 0)
	memcpy(ptr, CAP_HEADER_STRING, 20);
	ptr += 20;

	// add Master Key
	if (masterKeyId)
	{
		keylen = masterKeyLen;

		// add size of master key id
		*(short *)ptr = keylen;
		ptr += 2;

		// add master key id
		memcpy(ptr, masterKeyId, masterKeyLen);
		ptr += keylen;
	}
	else
	{
		// add size of master key id
		*(short *)ptr = 0;
		ptr += 2;
	}

	// add Data Key
	if (dataKeyId)
	{
		keylen = dataKeyLen;

		// add size of data key id
		*(short *)ptr = keylen;
		ptr += 2;

		// add data key id
		memcpy(ptr, dataKeyId, keylen);
		ptr += keylen;
	}
	else
	{
		// add size of master key id
		*(short *)ptr = 0;
		ptr += 2;
	}

	// add Usermd string
	if (usermdStr)
	{
		char *usermdDecodeStr;
		int usermdDecodeLen;

		// decode usermd string
		usermdDecodeLen = Base64decode_len(usermdStr);
		if (!(usermdDecodeStr = malloc(usermdDecodeLen+1)))
			goto ENCAP_FAILED;

		keylen = Base64decode(usermdDecodeStr, usermdStr);

		// add size of usermd
		*(short *)ptr = keylen;
		ptr += 2;

		// add usermd
		memcpy(ptr, usermdDecodeStr, keylen);
		ptr += keylen;

		free(usermdDecodeStr);
	}
	else
	{
		// add size of master key id
		*(short *)ptr = 0;
		ptr += 2;
	}

	// add tail
	memcpy(ptr, CAP_TAIL_STRING, 20);
	ptr += 20;

	// add NULL to end
	*ptr = 0;

	// get plaintext length
	keylen = Base64encode_len((int)(ptr-plaintxt));
	if (keylen > encapLen)
		goto ENCAP_FAILED;	

	// Base64 encode
	ret = Base64encode(encapStr, plaintxt, (int)(ptr-plaintxt)) -1;

	free(plaintxt);

	return ret;

ENCAP_FAILED:
	if (plaintxt)
		free(plaintxt);

	return -1;
}

int decap_metadata(const char *decapStr, int decapLen, 
				   char *masterKeyId, int *masterKeyLen, 
				   char *dataKeyId, int *dataKeyLen, 
				   char *usermdStr, int *usermdLen)
{
	int ret;
	int keylen;
	char *plaintxt;
	char *ptr;

	// check input parameter
	if (!decapStr)
		return -1;

	// calculate buffer size
	keylen = Base64decode_len(decapStr);
	plaintxt = malloc(keylen+1);
	if (!plaintxt)
		goto DECAP_FAILED;

	// Base64 decode
	ret = Base64decode(plaintxt, decapStr);
	if (ret < 49)	// 20+2+x+2+y+2+z+20 = 46 + xyz
		goto DECAP_FAILED;

	ptr = &plaintxt[0];

	// check header 
	if (memcmp(ptr, CAP_HEADER_STRING, 20))
		goto DECAP_FAILED;
	ptr += 20;

	// get Master Key
	{
		// size of master key Id 
		keylen = *(short *)ptr;
		if (keylen > *(masterKeyLen))
			goto DECAP_FAILED;
		ptr += 2;

		if (keylen > 0)
		{
			// get master key id
			memcpy(masterKeyId, ptr, keylen);
			masterKeyId[keylen] = 0;
			*(masterKeyLen) = keylen;
			ptr += keylen;
		}
	}

	// get Data Key
	{
		// size of data key Id 
		keylen = *(short *)ptr;
		if (keylen > *(dataKeyLen))
			goto DECAP_FAILED;
		ptr += 2;

		if (keylen > 0)
		{
			// get master key id
			memcpy(dataKeyId, ptr, keylen);
			dataKeyId[keylen] = 0;
			*(dataKeyLen) = keylen;
			ptr += keylen;
		}
	}

	// get Usermd string
	{
		// size of usermd
		keylen = *(short *)ptr;
		if (keylen > *(usermdLen))
			goto DECAP_FAILED;
		ptr += 2;

		if (keylen > 0)
		{
			char *usermdEncodeStr;

			if (!(usermdEncodeStr = malloc(keylen+1)))
				goto DECAP_FAILED;

			if (*(usermdLen) < Base64encode_len(keylen))
				goto DECAP_FAILED;

			// get usermd
			memcpy(usermdEncodeStr, ptr, keylen);
			usermdEncodeStr[keylen] = 0;
			ptr += keylen;

			*(usermdLen) = Base64encode(usermdStr, usermdEncodeStr, keylen);
			free(usermdEncodeStr);
		}
	}

	// check tail
	if (memcmp(ptr, CAP_TAIL_STRING, 20))
		goto DECAP_FAILED;
	ptr += 20;

	free(plaintxt);

	return 0;

DECAP_FAILED:
	if (plaintxt)
		free(plaintxt);

	return -1;
}