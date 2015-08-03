/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef AES256_H
#define AES256_H

EVP_CIPHER_CTX *InitAesCtr(unsigned char *keydata, int keydata_len);
void UninitAesCtr(EVP_CIPHER_CTX *ctx);
int EncryptAesCtr(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plainlen, unsigned char *ciphertext, unsigned char *keydata, int keydatalen);
int DecryptAesCtr(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int cipherlen, unsigned char *decryptedtext, unsigned char *keydata, int keydatalen);

#endif  /* AES256_H */

