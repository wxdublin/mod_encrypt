/* 
 * $Id: fcgi_protocol.h,v 1.1 1999/02/09 03:08:02 roberts Exp $
 */

#ifndef ENCAP_H
#define ENCAP_H

int encap_metadata(char *encapStr, int encapLen, 
				   const char *masterKeyId, int masterKeyLen, 
				   const char *dataKeyId, int dataKeyLen, 
				   const char *usermdStr, int usermdLen);

int decap_metadata(const char *decapStr, int decapLen, 
				   char *masterKeyId, int *masterKeyLen, 
				   char *dataKeyId, int *dataKeyLen, 
				   char *usermdStr, int *usermdLen);

#endif  /* ENCAP_H */

