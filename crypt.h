/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef CRYPT_H
#define CRYPT_H

#define CRYPT_BLOCK_SIZE	512

int InitEncrypt(fcgi_crypt * encryptor);
int InitDecrypt(fcgi_crypt * decryptor);
void CloseCrypt(fcgi_crypt * cryptor);
void CryptDataStream(fcgi_crypt * cryptor, char *data, int offset, int len);

#endif  /* CRYPT_H */

