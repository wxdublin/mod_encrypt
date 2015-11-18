/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef CRYPT_H
#define CRYPT_H

#define CRYPT_BLOCK_SIZE	512

int InitEncrypt(fcgienc_crypt * encryptor);
int InitDecrypt(fcgienc_crypt * decryptor);
void CloseCrypt(fcgienc_crypt * cryptor);
void CryptDataStream(fcgienc_crypt * cryptor, char *data, int offset, int len);

#endif  /* CRYPT_H */

