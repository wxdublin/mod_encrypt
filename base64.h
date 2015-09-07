#ifndef BASE64_H
#define BASE64_H

void b64_decode(char *b64src, char *clrdst);
void b64_encode(char *clrstr, char *b64dst);

#endif