/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef AES_H
#define AES_H

unsigned char *aes_encrypt(unsigned char *plaintext, int *len, unsigned char *key_data, int key_data_len);
unsigned char *aes_decrypt(unsigned char *ciphertext, int *len, unsigned char *key_data, int key_data_len);

#endif  /* AES_H */

