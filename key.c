#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "fcgi.h"
#include "memcache.h"
#include "json.h"
#include "utctime.h"
#include "key.h"
#include "base64.h"
#include "aes256cbc.h"

#define URL_SIZE 256
#define BUF_SIZE 1024
#define HEADER_SIZE 256
#define KEY_SIZE 256

static size_t bytesWritten = 0;
static size_t bytesRead = 0;

static int key_calculate_real(request_rec * r, fcgi_crypt * fc, char *keyencbase64);

static size_t writeFn(void* buf, size_t len, size_t size, void* userdata) {
	size_t sLen = len * size;

	// if this is zero, then it's done
	// we don't do any special processing on the end of the stream
	if (sLen > 0) {
		// >= to account for terminating null
		if (bytesWritten + sLen >= BUF_SIZE) {
			return 0;
		}

		memcpy(&((char*)userdata)[bytesWritten], buf, sLen);
		bytesWritten += sLen;
	}

	return sLen;
}

static size_t readFn(void* ptr, size_t size, size_t nmemb, void* userdata) {
	size_t tLen;
	char* str;
	if (!userdata) {
		return 0;
	}

	str = (char*)userdata;
	tLen = strlen(&str[bytesRead]);
	if (tLen > size * nmemb) {
		tLen = size * nmemb;
	}

	if (tLen > 0) {
		// assign the string as the data to be sent
		memcpy(ptr, &str[bytesRead], tLen);
		bytesRead += tLen;
	}

	return tLen;
}

int key_auth_request(request_rec * r, fcgi_crypt * fc, const char *server)
{
	int ret;
	CURL *curl = NULL;
	CURLcode res;
	char serverurl[URL_SIZE];
	char senddata[BUF_SIZE];
	char recvdata[BUF_SIZE];
	char *token;
	char *timestring = NULL;
	void *jsonhandler = NULL;
	unsigned int timediff;
	char keyname[KEY_SIZE];
	struct curl_slist* headers = NULL;
	const char *mks;

	// check parameters
	if (!fcgi_username || !fcgi_password || !server)
		return -1;

	mks = server;

	// if already exist in memcache
	memset(keyname, 0, KEY_SIZE);
	sprintf(keyname, "%s-%s-auth", mks, fcgi_username);
	token = memcache_get(keyname);
	if (token)
	{
		// already exist
		memcpy(fc->token, token, strlen(token));
		fc->token[strlen(token)] = 0;
		return 0;
	}

	// add the application/json content-type
	// so the server knows how to interpret our HTTP POST body
	headers = curl_slist_append(headers, "Content-Type: application/json");

	// create serverurl
	memset(serverurl, 0, URL_SIZE);
	memset(senddata, 0, BUF_SIZE);
	memset(recvdata, 0, BUF_SIZE);
	sprintf(serverurl, "http://%s/auth", mks);
	sprintf(senddata, "{\"username\":\"%s\",\"password\":\"%s\"}", fcgi_username, fcgi_password);

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if(curl) 
	{
		bytesWritten = 0;
		bytesRead = 0;

		// setup curl
		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(senddata));
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, readFn);
		curl_easy_setopt(curl, CURLOPT_READDATA, senddata);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			ret = -1;
			goto AUTH_REQUEST_EXIT;
		}

		/* always cleanup */ 
		curl_slist_free_all( headers ) ; headers = NULL;
		curl_easy_cleanup(curl); curl = NULL;
	}

	curl_global_cleanup();

	// process json response
	jsonhandler = json_load(recvdata);

	// get token
	token = json_get_string(jsonhandler, "token");
	if (!token)
	{
		ret = -1;
		goto AUTH_REQUEST_EXIT;
	}

	// expiration_time: <UTC time when the token will expire; e.g. 2015-08-11T20:31:17.341Z>
	timestring = json_get_string(jsonhandler, "expiration_time");
	if (!timestring)
	{
		ret = -1;
		goto AUTH_REQUEST_EXIT;
	}

	// store token
	memcpy(fc->token, token, strlen(token));
	fc->token[strlen(token)] = 0;

	// store into memcache
	timediff = time_utc_diff(timestring);
	memset(keyname, 0, KEY_SIZE);
	sprintf(keyname, "%s-%s-auth", mks, fcgi_username);
	memcache_set_timeout(keyname, fc->token, timediff);

	ret = 0;

AUTH_REQUEST_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);

	return ret;
}

int key_master_request(request_rec * r, fcgi_crypt * fc, const char *server)
{
	int ret;
	CURL *curl = NULL;
	CURLcode res;
	char serverurl[URL_SIZE];
	char recvdata[BUF_SIZE];
	char headerstring[HEADER_SIZE];
	void *jsonhandler = NULL;
	char *masterkeyid = NULL;
	char *masterkey = NULL;
	int refreshinterval;
	char *initializationvector = NULL;
	struct curl_slist* headers = NULL;
	const char *mks;

	// check parameters
	if (!fcgi_username || !fcgi_password || !fc->token || !server)
		return -1;

	mks = server;

	// make request header
	memset(headerstring, 0, HEADER_SIZE);
	sprintf(headerstring, "Authorization: Token %s", fc->token);
	headers = curl_slist_append(headers, headerstring);

	// make request url
	memset(serverurl, 0, URL_SIZE);
	memset(recvdata, 0, BUF_SIZE);
	if (fc->masterKeyId)
		sprintf(serverurl, "http://%s/master/key/%s", mks, fc->masterKeyId);
	else
		sprintf(serverurl, "http://%s/master/key", mks);

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) {
		bytesWritten = 0;
		bytesRead = 0;

		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n",	curl_easy_strerror(res));
			ret = -1;
			goto MASTERKEY_EXIT;
		}

		/* always cleanup */ 
		curl_easy_cleanup(curl); curl = NULL;
		curl_slist_free_all( headers ) ; headers = NULL;
	}

	curl_global_cleanup();

	// process json response
	jsonhandler = json_load(recvdata);

	// get key_id
	masterkeyid = json_get_string(jsonhandler, "key_id");
	if (!masterkeyid)
	{
		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// get refresh time
	refreshinterval = json_get_integer(jsonhandler, "refresh_interval");
	if (refreshinterval < 0)
	{
		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// get key
	masterkey = json_get_string(jsonhandler, "key");
	if (!masterkey)
	{
		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// get initialization vector
	initializationvector = json_get_string(jsonhandler, "initialization_vector");
	if (!initializationvector)
	{
		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// store into variable
	memcpy(fc->masterKeyId, masterkeyid, strlen(masterkeyid));
	fc->masterKeyId[strlen(masterkeyid)] = 0;

	memcpy(fc->masterKey, masterkey, strlen(masterkey));
	fc->masterKey[strlen(masterkey)] = 0;

	memcpy(fc->initializationVector, initializationvector, strlen(initializationvector));
	fc->initializationVector[strlen(initializationvector)] = 0;

	ret = 0;

MASTERKEY_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);
	return ret;
}

int key_data_request(request_rec * r, fcgi_crypt * fc, const char *server)
{
	int ret;
	CURL *curl;
	CURLcode res;
	char serverurl[URL_SIZE];
	char recvdata[BUF_SIZE];
	char headerstring[HEADER_SIZE];
	void *jsonhandler=NULL;
	char *masterkeyid = NULL;
	char *datakeyid = NULL;
	int refreshinterval;
	char *keyencryptedbase64 = NULL;
	struct curl_slist* headers = NULL;
	const char *dks;

	// check parameters
	if (!fcgi_username || !fcgi_password || !fc->token || !server)
		return -1;

	dks = server;

	// make request header
	memset(headerstring, 0, HEADER_SIZE);
	sprintf(headerstring, "Authorization: Token %s", fc->token);
	headers = curl_slist_append(headers, headerstring);

	// make request url
	memset(serverurl, 0, URL_SIZE);
	memset(recvdata, 0, BUF_SIZE);
	if (fc->dataKeyId)
		sprintf(serverurl, "http://%s/data/key/%s", dks, fc->dataKeyId);
	else
		sprintf(serverurl, "http://%s/data/key", dks);

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) {
		bytesWritten = 0;
		bytesRead = 0;

		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n",	curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			curl_slist_free_all( headers ) ;
			return -1;
		}

		/* always cleanup */ 
		curl_easy_cleanup(curl); curl = NULL;
		curl_slist_free_all( headers ) ; headers = NULL;
	}

	curl_global_cleanup();

	// process json response
	jsonhandler = json_load(recvdata);

	// get data key id
	datakeyid = json_get_string(jsonhandler, "key_id");
	if (!datakeyid)
	{
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// get master key id
	masterkeyid = json_get_string(jsonhandler, "master_key_id");
	if (!masterkeyid)
	{
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// get refresh interval
	refreshinterval = json_get_integer(jsonhandler, "refresh_interval");
	if (refreshinterval < 0)
	{
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// get key encrypted base64
	keyencryptedbase64 = json_get_string(jsonhandler, "key_encrypted_base64");
	if (!keyencryptedbase64)
	{
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// store into variable
	memcpy(fc->dataKeyId, datakeyid, strlen(datakeyid));
	fc->dataKeyId[strlen(datakeyid)] = 0;

	ret = key_calculate_real(r, fc, keyencryptedbase64);

DATAKEY_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);
	return ret;
}

static int key_calculate_real(request_rec * r, fcgi_crypt * fc, char *keyencbase64)
{
	int i, len;
	char mkhex[32], ivhex[16];
	char keyencrypted[KEY_SIZE];
	char keydecrypted[KEY_SIZE];

	if (!keyencbase64 || !fc->masterKey || !fc->initializationVector)
		return -1;

	memset(mkhex, 0, 32);
	len = strlen(fc->masterKey)&0xFFFFFFFE;
	for (i=0; i<len; i+=2)
	{
		char c[3];
		if (i>=64)
			break;
		c[0] = fc->masterKey[i];
		c[1] = fc->masterKey[i+1];
		c[2] = 0;
		sscanf(c, "%x", (unsigned int *)&mkhex[i/2]);
	}
	if ((i<64) && (len < strlen(fc->masterKey)))
	{
		char c[3];
		c[0] = fc->masterKey[len];
		c[1] = '0';
		c[2] = 0;
		sscanf(c, "%x", (unsigned int *)&mkhex[i/2]);
	}

	memset(ivhex, 0, 16);
	len = strlen(fc->initializationVector)&0xFFFFFFFE;
	for (i=0; i<len; i+=2)
	{
		char c[3];
		if (i>=32)
			break;
		c[0] = fc->initializationVector[i];
		c[1] = fc->initializationVector[i+1];
		c[2] = 0;
		sscanf(c, "%x", (unsigned int *)&ivhex[i/2]);
	}
	if ((i<32) && (len < strlen(fc->initializationVector)))
	{
		char c[3];
		c[0] = fc->initializationVector[len];
		c[1] = '0';
		c[2] = 0;
		sscanf(c, "%x", (unsigned int *)&ivhex[i/2]);
	}

	// decode base64
	b64_decode(keyencbase64, keyencrypted);

	// decrypt key
	memset(keydecrypted, 0, KEY_SIZE);
	len = DecryptAesCBC(keyencrypted, (int)strlen(keyencrypted), keydecrypted, mkhex, ivhex);
	if (len < 0)
		return -1;

	// store into variable
	memcpy(fc->dataKey, keydecrypted, len);
	fc->dataKey[len] = 0;
	fc->dataKeyLength = len;

	return 0;
}
