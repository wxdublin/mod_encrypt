/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef AES256CBC_H
#define AES256CBC_H

int EncryptAesCBC(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *key, unsigned char *iv);
int DecryptAesCBC(unsigned char *ciphertext, int ciphertext_len, unsigned char *decryptedtext, unsigned char *key, unsigned char *iv);

#endif  /* AES256CBC_H */

