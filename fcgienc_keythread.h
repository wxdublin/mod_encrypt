/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _FCGIENC_KEY_THREAD_H__
#define _FCGIENC_KEY_THREAD_H__

#ifdef WIN32
/* warning C4115: named type definition in parentheses */
#pragma warning(disable : 4115)
/* warning C4514: unreferenced inline function has been removed */
#pragma warning(disable:4514)
/* warning C4244: conversion from 64 to 32 has been removed */
#pragma warning(disable:4244)
/* warning C4267: conversion from size_t to 32 has been removed */
#pragma warning(disable:4267)
#endif

// Lengths
#define URL_SIZE 400
#define BUF_SIZE 1024
#define HEADER_SIZE 256
#define KEY_SIZE 256

// Cache keys
#define CACHE_KEYNAME_AUTHTOKEN			"fcgi-auth-token"
#define CACHE_KEYNAME_MAKSTERKEYID		"fcgi-master-keyid"
#define CACHE_KEYNAME_MAKSTERKEY		"fcgi-master-key"
#define CACHE_KEYNAME_IV				"fcgi-master-iv"
#define CACHE_KEYNAME_DATAKEYID			"fcgi-data-keyid"
#define CACHE_KEYNAME_ENCRYPTEDDATAKEY	"fcgi-data-encryptedkey"
#define CACHE_KEYNAME_DATAKEY			"fcgi-data-key"

#define KEY_STORE_PERIOD		(7*24*3600)			// a week

/*
* fcgi_request holds the state of a particular Encrypt request.
*/
typedef struct {
	void *crypt;
	int offset;

	char token[256];
	char masterKeyId[256];
	char masterKey[256];
	char initializationVector[256];
	char dataKeyId[256];
	char encryptedDataKey[256];
	char dataKey[256];
	int dataKeyLength;
} fcgienc_crypt;

#endif // _FCGIENC_KEY_THREAD_H__
