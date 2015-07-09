#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

unsigned char *sha256(char *data, int len)
{
    unsigned char *md;

	if (data == NULL)
		return NULL;

	md = malloc(SHA256_DIGEST_LENGTH);

	EVP_Digest(data, len, md, NULL, EVP_sha256(), NULL);

    return md;
}
