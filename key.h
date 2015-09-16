/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _KEY_H__
#define _KEY_H__

// Lengths
#define URL_SIZE 256
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

//#define KEY_STORE_PERIOD		(7*24*3600)			// a week
#define KEY_STORE_PERIOD		(1*1*60)			// a week

int key_active_request(fcgi_crypt * fc);
int key_old_request(fcgi_crypt * fc);

#endif // _KEY_H__
