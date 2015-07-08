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

#include "aes.h"

static unsigned char keyData[] = "abcdefghijklmnopqrstuvwxyz1234567890";
static int keyLen = 36;

 /*******************************************************************************
 * Encrypt any data by crypt key
 */
char *encrypt_data(char *data, int *len)
{
	return aes_encrypt(data, len, keyData, keyLen);
}

 /*******************************************************************************
 * Decryt any data by crypt key
 */
char *decrypt_data(char *data, int *len)
{
	return aes_decrypt(data, len, keyData, keyLen);
}

//  /*******************************************************************************
//  * Encrypt any data by crypt key
//  */
// void encrypt_data(char *data, int len)
// {
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
// 
// // 	int outLen1 = 0; int outLen2 = 0;
// // 	unsigned char *indata = NULL, *outdata = NULL;
// // 	EVP_CIPHER_CTX ctx;
// // 	
// // 	indata = malloc(len);
// // 	outdata = malloc(len*2);
// // 	
// // 	// copy data
// // 	memcpy(indata, data, len);
// // 
// // 	//Set up encryption
// // 	EVP_EncryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
// // 	EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,len);
// // 	EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
// // 	//fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);
// // 
// // 	free(indata);
// // 	free(outdata);
// }
// 
//  /*******************************************************************************
//  * Decrypt any data by crypt key
//  */
// void decrypt_data(char *data, int len)
// {
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
// 
// // 	int outLen1 = 0; int outLen2 = 0;
// // 	unsigned char *indata = NULL, *outdata = NULL;
// // 	EVP_CIPHER_CTX ctx;
// // 
// // 	indata = malloc(len);
// // 	outdata = malloc(len);
// // 
// // 	// copy data
// // 	memcpy(indata, data, len);
// // 
// // 	//setup decryption
// // 	EVP_DecryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
// // 	EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,len);
// // 	EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);
// // 	//fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);
// // 
// // 	free(indata);
// // 	free(outdata);
// }
