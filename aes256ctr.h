/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef AES256CTR_H
#define AES256CTR_H

EVP_CIPHER_CTX *InitAesCtr(unsigned char *keydata, int keydata_len);
void UninitAesCtr(EVP_CIPHER_CTX *ctx);
int CryptAesCtr(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plainlen, unsigned char *ciphertext);

#endif  /* AES256_H */

