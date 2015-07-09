/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef AES256_H
#define AES256_H

unsigned char *aes256_enc(unsigned char *plaintext, int *len, unsigned char *key_data, int key_data_len);
unsigned char *aes256_dec(unsigned char *ciphertext, int *len, unsigned char *key_data, int key_data_len);

#endif  /* AES256_H */

