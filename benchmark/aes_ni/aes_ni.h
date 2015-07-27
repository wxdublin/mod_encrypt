#ifndef _AESNI_H__
#define _AESNI_H__

#include "iaes_asm_interface.h"

#if (__cplusplus)
extern "C" {
#endif

void aesni_encrypt(unsigned char *input, int *len, unsigned char *output);
void aesni_decrypt(unsigned char *input, int *len, unsigned char *output);
void aesnoni_encrypt(unsigned char *input, int *len, unsigned char *output);
void aesnoni_decrypt(unsigned char *input, int *len, unsigned char *output);

#if (__cplusplus)
}
#endif

#endif



