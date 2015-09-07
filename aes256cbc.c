#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	
	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits 
	 */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;
	
	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;
	ciphertext_len = len;
	
	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return -1;
	ciphertext_len += len;
	
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_len;
}

static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		return -1;
	
	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;
	
	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return -1;
	plaintext_len = len;
	
	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
		return -1;
	plaintext_len += len;
	
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_len;
}

// /* A 256 bit key */
// unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
// 
// /* A 128 bit IV */
// unsigned char *iv = (unsigned char *)"01234567890123456";
// 
// /* Message to be encrypted */
// unsigned char *plaintext =
// (unsigned char *)"The quick brown fox jumps over the lazy dog";

int EncryptAesCBC(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *key, unsigned char *iv)
{
	int ciphertext_len;

	if (!plaintext || !ciphertext || !key || !iv)
		return -1;
	
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
	/* Encrypt the plaintext */
	ciphertext_len = encrypt (plaintext, plaintext_len, key, iv, ciphertext);
	
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
	
	return ciphertext_len;
}

int DecryptAesCBC(unsigned char *ciphertext, int ciphertext_len, unsigned char *decryptedtext, unsigned char *key, unsigned char *iv)
{
	int decryptedtext_len;

	if (!ciphertext || !decryptedtext || !key || !iv)
		return -1;
	
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
	if (decryptedtext_len <0)
	{
		/* Clean up */
		EVP_cleanup();
		ERR_free_strings();
		return -1;
	}
	
	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';
	
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return decryptedtext_len;
}