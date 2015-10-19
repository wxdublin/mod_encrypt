#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "aes256ctr.h"

#define CRYPT_CBC_MODE	0
#define CRYPT_CTR_MODE	1

//////////////////////////////////////////////////////////////////////////
/* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 */
static unsigned int gSalt[] = {12345, 54321};

//////////////////////////////////////////////////////////////////////////

static int handleErrors(void)
{
	return -1;
}

static int encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(ctx == NULL) 
		return handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return handleErrors();
	ciphertext_len = +len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	return ciphertext_len;
}

EVP_CIPHER_CTX *InitAesCtr(unsigned char *keydata, int keydata_len)
{
	int i, nrounds = 1;
	unsigned char key[32], iv[32];
	EVP_CIPHER_CTX *ctx;

	/* Check input parameters */
	if ((!keydata) || (keydata_len == 0))
		return NULL;

	/* Initialize the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Create and initialize the encryption context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		return NULL;

	/*
	* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	* nrounds is the number of times the we hash the material. More rounds are more secure but
	* slower.
	*/
	i = EVP_BytesToKey(EVP_aes_256_ctr(), EVP_sha1(), (unsigned char *)&gSalt, keydata, keydata_len, nrounds, key, iv);
	if (i != 32) {
		//printf("Key size is %d bits - should be 256 bits\n", i);
		return NULL;
	}

	/* Initialize the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
		return NULL;

	return ctx;
}

void UninitAesCtr(EVP_CIPHER_CTX *ctx)
{
	if (!ctx)
		return;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
}

int CryptAesCtr(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plainlen, unsigned char *ciphertext)
{
	int cipher_len;

	/* Encrypt the plaintext */
	cipher_len = encrypt(ctx, plaintext, plainlen, ciphertext);

	return cipher_len;
}
