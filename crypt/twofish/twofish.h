/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef TWOFISH_H
#define TWOFISH_H

#include "std_defs.h"

u4byte *twofish_set_key(const u4byte in_key[], const u4byte key_len);
u4byte *twofish_encrypt(const u4byte in_blk[4]);
u4byte *twofish_decrypt(const u4byte in_blk[4]);

#endif  /* TWOFISH_H */

