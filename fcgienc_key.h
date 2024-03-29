/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _FCGIENC_KEY_H__
#define _FCGIENC_KEY_H__

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

int key_active_request(fcgienc_crypt * fc);
int key_old_request(fcgienc_crypt * fc);

#endif // _FCGIENC_KEY_H__
