#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define AES_BLOCK_SIZE 512

/* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 */
unsigned int SALT[] = {12345, 54321};

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes256_enc(unsigned char *plaintext, int *len, unsigned char *key_data, int key_data_len)
{
	EVP_CIPHER_CTX en;
	int i, nrounds = 5;
	unsigned char key[32], iv[32];
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);
	
	/*
	* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	* nrounds is the number of times the we hash the material. More rounds are more secure but
	* slower.
	*/
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char *)&SALT, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		//printf("Key size is %d bits - should be 256 bits\n", i);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&en);
	EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(), NULL, key, iv);
	
	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	*len is the size of plaintext in bytes */
	EVP_EncryptUpdate(&en, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(&en, ciphertext+c_len, &f_len);

	*len = c_len + f_len;

	EVP_CIPHER_CTX_cleanup(&en);

	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes256_dec(unsigned char *ciphertext, int *len, unsigned char *key_data, int key_data_len)
{
	EVP_CIPHER_CTX de;
	int i, nrounds = 5;
	unsigned char key[32], iv[32];
	/* plaintext will always be equal to or lesser than length of ciphertext*/
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len);

	/*
	* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	* nrounds is the number of times the we hash the material. More rounds are more secure but
	* slower.
	*/
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char *)&SALT, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		//printf("Key size is %d bits - should be 256 bits\n", i);
		return NULL;
	}
	
	EVP_CIPHER_CTX_init(&de);
	EVP_DecryptInit_ex(&de, EVP_aes_256_cbc(), NULL, key, iv);

	EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(&de, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(&de, plaintext+p_len, &f_len);
	
	*len = p_len + f_len;

	EVP_CIPHER_CTX_cleanup(&de);

	return plaintext;
}
