/*
 * $Id: fcgi_protocol.c,v 1.27 2008/09/23 14:48:13 robs Exp $
 */

#ifdef APACHE2
#include "apr_lib.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

 /*******************************************************************************
 * Crypt keys
 */
static unsigned char ckey[] =  "thiskeyisverybad";
static unsigned char ivec[] = "dontusethisinput";

 /*******************************************************************************
 * Encryt any data by crypt key
 */
void encrypt_data(char *data, int len)
{
// 	int i;
// 
// 	for (i=0; i<len; i++)
// 	{
// 		// 'A'->'a', 'a'->'A'
// 		if ((data[i]>=0x41) && (data[i]<=0x5A))
// 			data[i] += 0x20;
// 		else if ((data[i]>=0x61) && (data[i]<=0x7A))
// 			data[i] -= 0x20;
// 	}

	int outLen1 = 0; int outLen2 = 0;
	unsigned char *indata = NULL, *outdata = NULL;
	EVP_CIPHER_CTX ctx;
	
	indata = malloc(len);
	outdata = malloc(len*2);
	
	// copy data
	memcpy(indata, data, len);

	//Set up encryption
	EVP_EncryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
	EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,len);
	EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
	//fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

	free(indata);
	free(outdata);
}

 /*******************************************************************************
 * Decryt any data by crypt key
 */
void decrypt_data(char *data, int len)
{
// 	int i;
// 
// 	for (i=0; i<len; i++)
// 	{
// 		// 'A'->'a', 'a'->'A'
// 		if ((data[i]>=0x41) && (data[i]<=0x5A))
// 			data[i] += 0x20;
// 		else if ((data[i]>=0x61) && (data[i]<=0x7A))
// 			data[i] -= 0x20;
// 	}

	int outLen1 = 0; int outLen2 = 0;
	unsigned char *indata = NULL, *outdata = NULL;
	EVP_CIPHER_CTX ctx;

	indata = malloc(len);
	outdata = malloc(len);

	// copy data
	memcpy(indata, data, len);

	//setup decryption
	EVP_DecryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
	EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,len);
	EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);
	//fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

	free(indata);
	free(outdata);
}
