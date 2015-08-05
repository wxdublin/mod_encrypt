/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef CRYPT_H
#define CRYPT_H

#define CRYPT_BLOCK_SIZE	512

void *InitCrypt(unsigned char *keydata, int keydata_len);
void CloseCrypt(void *ctx);
void CryptDataStream(void *ctx, char *data, int offset, int len);

#endif  /* CRYPT_H */

