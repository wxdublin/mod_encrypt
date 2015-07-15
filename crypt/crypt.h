/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef CRYPT_H
#define CRYPT_H

#define CRYPT_BLOCK_SIZE	512

char *encrypt_data(char *data, int *len);
char *decrypt_data(char *data, int *len);
void encrypt_data_stream(char *data, int offset, int len, int csc);
void decrypt_data_stream(char *data, int offset, int len, int csc);

#endif  /* CRYPT_H */

