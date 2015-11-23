#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#ifndef WIN32
#include <unistd.h>
#endif
#include "fcgienc.h"
#include "fcgienc_memcache.h"
#include "fcgienc_json.h"
#include "fcgienc_utctime.h"
#include "fcgienc_key.h"
#include "fcgienc_base64.h"
#include "fcgienc_aes256cbc.h"
#include "fcgienc_log.h"


//////////////////////////////////////////////////////////////////////////
/**
 * Calculate the real key from master key, encrypted data key
 */
static int key_calculate_real(fcgienc_crypt * fc)
{
	int i;
	size_t len;
	unsigned char mkhex[32], ivhex[16];
	char decodebuf[KEY_SIZE];
	int decodelen;
	unsigned char keystr[KEY_SIZE];
	char *keyencbase64;

	if (!fc)
		return -1;

	keyencbase64 = fc->encryptedDataKey;

	// string -> hex of master key 
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

	// string -> hex of data key
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
	decodelen = Base64decode(decodebuf, keyencbase64);

	// decrypt key
	memset(keystr, 0, KEY_SIZE);
	len = DecryptAesCBC((unsigned char *)decodebuf, decodelen, keystr, mkhex, ivhex);

	if (len < 0)
		return -1;

	// store into variable
	memcpy(fc->dataKey, keystr, len);
	fc->dataKey[len] = 0;
	fc->dataKeyLength = len;

	return 0;
}

//////////////////////////////////////////////////////////////////////////

static size_t writeFn(void* buf, size_t len, size_t size, void* userdata) {
	size_t sLen = len * size;
	char* str;
	size_t bytesWritten;

	str = (char*)userdata;
	// if this is zero, then it's done
	// we don't do any special processing on the end of the stream
	if (sLen > 0) {
		bytesWritten = (size_t)*((unsigned short *)&str[BUF_SIZE]);
		// >= to account for terminating null
		if (bytesWritten + sLen >= BUF_SIZE) {
			return 0;
		}

		memcpy(&str[bytesWritten], buf, sLen);
		bytesWritten += sLen;
		*((unsigned short *)&str[BUF_SIZE]) = (unsigned short)bytesWritten;
	}

	return sLen;
}

static size_t readFn(void* ptr, size_t size, size_t nmemb, void* userdata) {
	size_t tLen;
	char* str;
	size_t bytesRead;

	if (!userdata) {
		return 0;
	}

	str = (char*)userdata;
	bytesRead = (size_t)*((unsigned short *)&str[BUF_SIZE]);
	tLen = strlen(&str[bytesRead]);
	if (tLen > size * nmemb) {
		tLen = size * nmemb;
	}

	if (tLen > 0) {
		// assign the string as the data to be sent
		memcpy(ptr, &str[bytesRead], tLen);
		bytesRead += tLen;
		*((unsigned short *)&str[BUF_SIZE]) = (unsigned short)bytesRead;
	}

	return tLen;
}

/**
 * Get Authentication Token from server
 */
static int get_auth_token(char *tokenstr)
{
	int ret;
	CURL *curl = NULL;
	CURLcode res;
	char serverurl[URL_SIZE];
	char senddata[BUF_SIZE+2];
	char recvdata[BUF_SIZE+2];
	char *token;
	char *timestring = NULL;
	void *jsonhandler = NULL;
	int timediff;
	struct curl_slist* headers = NULL;
	size_t len;

	// check parameters
	if (!tokenstr)
		return -1;

	// add the application/json content-type
	// so the server knows how to interpret our HTTP POST body
	headers = curl_slist_append(headers, "Content-Type: application/json");

	// create serverurl
	memset(serverurl, 0, URL_SIZE);
	memset(senddata, 0, BUF_SIZE+2);
	memset(recvdata, 0, BUF_SIZE+2);
	sprintf(serverurl, "http://%s/auth", fcgienc_authserver);
	sprintf(senddata, "{\"username\":\"%s\",\"password\":\"%s\"}", fcgienc_username, fcgienc_password);

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if(curl) 
	{
		// setup curl
		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
		// curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		// curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(senddata));
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, readFn);
		curl_easy_setopt(curl, CURLOPT_READDATA, (void *)senddata);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl request : %s, senddata : %s", serverurl, senddata);

		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl failed : %s", curl_easy_strerror(res));

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
	log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl response : %s", recvdata);

	// get token
	token = json_get_string(jsonhandler, "token");
	if (!token)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"token\" in response : %s", recvdata);
		ret = -1;
		goto AUTH_REQUEST_EXIT;
	}

	// expiration_time: <UTC time when the token will expire; e.g. 2015-08-11T20:31:17.341Z>
	timestring = json_get_string(jsonhandler, "expiration_time");
	if (!timestring)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"expiration_time\" in response : %s", recvdata);
		ret = -1;
		goto AUTH_REQUEST_EXIT;
	}

	// store token
	len = strlen(token);
	if (len > 255)
		len = 255;
	memcpy(tokenstr, token, len);
	tokenstr[len] = 0;

	// store into memcache
	timediff = (int)time_utc_diff(timestring);

	ret = timediff;

AUTH_REQUEST_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);

	return ret;
}

/**
 * Get Master Key from server
 */
static int get_master_key(const char *token, char *masterkeyid, char *masterkey, char *iv)
{
	int ret;
	int timeout;
	CURL *curl = NULL;
	CURLcode res;
	char serverurl[URL_SIZE];
	char recvdata[BUF_SIZE+2];
	char headerstring[HEADER_SIZE];
	char *jsonmasterkeyid, *jsonmasterkey, *jsoniv;
	void *jsonhandler = NULL;
	struct curl_slist* headers = NULL;
	size_t len;

	// check parameters
	if (!token || !masterkeyid || !masterkey || !iv)
		return -1;

	// make request header
	memset(headerstring, 0, HEADER_SIZE);
	sprintf(headerstring, "Authorization: Token %s", token);
	headers = curl_slist_append(headers, headerstring);

	// make request url
	memset(serverurl, 0, URL_SIZE);
	memset(recvdata, 0, BUF_SIZE+2);
	if (strlen(masterkeyid) > 0)
		sprintf(serverurl, "http://%s/master/key/%s", fcgienc_masterkeyserver, masterkeyid);
	else
		sprintf(serverurl, "http://%s/master/key", fcgienc_masterkeyserver);

	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
		// curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		// curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl request : %s, header : %s", serverurl, headerstring);

		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl failed : %s", curl_easy_strerror(res));
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
	log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl response : %s", recvdata);

	// get key_id
	jsonmasterkeyid = json_get_string(jsonhandler, "key_id");
	if (!jsonmasterkeyid)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"master key id\" in response : %s", recvdata);
		ret = -1;
		goto MASTERKEY_EXIT;
	}
	if (strcmp(jsonmasterkeyid, masterkeyid))
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - unmatched master key id in old-%s : new-%s", masterkeyid, jsonmasterkeyid);
	}

	// get refresh time
	timeout = json_get_integer(jsonhandler, "refresh_interval");
	if (timeout < 0)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"master key refresh_interval\" in response : %s", recvdata);

		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// get key
	jsonmasterkey = json_get_string(jsonhandler, "key");
	if (!jsonmasterkey)
	{
		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// get initialization vector
	jsoniv = json_get_string(jsonhandler, "initialization_vector");
	if (!jsoniv)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"initialization_vector\" in response : %s", recvdata);

		ret = -1;
		goto MASTERKEY_EXIT;
	}

	// store into variable
	len = strlen(jsonmasterkey);
	if (len > 255)
		len = 255;
	memcpy(masterkey, jsonmasterkey, len);
	masterkey[len] = 0;

	len = strlen(jsoniv);
	if (len > 255)
		len = 255;
	memcpy(iv, jsoniv, len);
	iv[len] = 0;

	ret = timeout;

MASTERKEY_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);
	return ret;
}

/**
 * Get Data Key from server
 */
static int get_data_key(const char *token, char *masterkeyid, char *datakeyid, char *datakey)
{
	int ret;
	CURL *curl;
	CURLcode res;
	char serverurl[URL_SIZE];
	char recvdata[BUF_SIZE+2];
	char headerstring[HEADER_SIZE];
	void *jsonhandler=NULL;
	char *jsonmasterkeyid = NULL;
	char *jsondatakeyid = NULL;
	int timeout;
	char *jsonkeyencryptedbase64 = NULL;
	struct curl_slist* headers = NULL;
	size_t len;

	// make request header
	memset(headerstring, 0, HEADER_SIZE);
	sprintf(headerstring, "Authorization: Token %s", token);
	headers = curl_slist_append(headers, headerstring);

	// make request url
	memset(serverurl, 0, URL_SIZE);
	memset(recvdata, 0, BUF_SIZE+2);
	if (strlen(datakeyid) > 0)
		sprintf(serverurl, "http://%s/data/key/%s", fcgienc_datakeyserver, datakeyid);
	else
		sprintf(serverurl, "http://%s/data/key", fcgienc_datakeyserver);

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, serverurl);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)recvdata);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl request : %s, header : %s", serverurl, headerstring);

		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl failed : %s", curl_easy_strerror(res));

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
	log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - curl response : %s", recvdata);

	// get data key id
	jsondatakeyid = json_get_string(jsonhandler, "key_id");
	if (!jsondatakeyid)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"data key id\" in response : %s", recvdata);

		ret = -1;
		goto DATAKEY_EXIT;
	}

	// get master key id
	jsonmasterkeyid = json_get_string(jsonhandler, "master_key_id");
	if (!jsonmasterkeyid)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found master key id in response : %s", recvdata);

		ret = -1;
		goto DATAKEY_EXIT;
	}
	if (strcmp(jsonmasterkeyid, masterkeyid))
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - unmatched master key id in old-%s : new-%s", masterkeyid, jsonmasterkeyid);
		len = strlen(jsonmasterkeyid);
		if (len > 255)
			len = 255;
		memcpy(masterkeyid, jsonmasterkeyid, len);
		masterkeyid[len] = 0;
	}

	// get refresh interval
	timeout = json_get_integer(jsonhandler, "refresh_interval");
	if (timeout < 0)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"data key refresh_interval\" in response : %s", recvdata);
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// get key encrypted base64
	jsonkeyencryptedbase64 = json_get_string(jsonhandler, "key_encrypted_base64");
	if (!jsonkeyencryptedbase64)
	{
		log_message(ENCRYPT_LOG_DEBUG, "KEY-THREAD - not found \"key_encrypted_base64\" in response : %s", recvdata);
		ret = -1;
		goto DATAKEY_EXIT;
	}

	// store into variable
	len = strlen(jsondatakeyid);
	if (len > 255)
		len = 255;
	memcpy(datakeyid, jsondatakeyid, len);
	datakeyid[len] = 0;
	
	len = strlen(jsonkeyencryptedbase64);
	if (len > 255)
		len = 255;
	memcpy(datakey, jsonkeyencryptedbase64, len);
	datakey[len] = 0;

	ret = timeout;

DATAKEY_EXIT:
	if (headers) curl_slist_free_all( headers ) ;
	if (curl) curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (jsonhandler) json_unload(jsonhandler);
	return ret;
}

/**
 * Thread entry point
 */
void* APR_THREAD_FUNC key_thread_func(apr_thread_t *thd, void *params)
{
	int ret;
	fcgienc_crypt fc;
	int timeout;
	int authtimeout, mktimeout, dktimeout;
	
	// check parameters
	if (!fcgienc_username || !fcgienc_password || !fcgienc_authserver || \
		!fcgienc_masterkeyserver || !fcgienc_datakeyserver)
	{
		apr_thread_exit(thd, APR_SUCCESS);
		return NULL;
	}

	// init timeout values
	authtimeout = mktimeout = dktimeout = 0;
	while (1)
	{
		timeout = 0;

		// Authentication Token
		authtimeout -= 30;
		if (authtimeout <= 30)
		{
			fc.token[0] = 0;
			timeout = get_auth_token(fc.token);
			if (timeout > 0)
			{
				memcache_set(CACHE_KEYNAME_AUTHTOKEN, fc.token, timeout);
				authtimeout = timeout;
				mktimeout = dktimeout = -1;
			}
			else
			{
				goto KEY_ERROR;
			}
		}
		ret = memcache_get(CACHE_KEYNAME_AUTHTOKEN, fc.token);
		if (ret < 0)
		{
			goto KEY_ERROR;
		}

		// Data Key
		dktimeout -= 30;
		if (dktimeout <= 30)
		{
			fc.dataKeyId[0] = 0;
			fc.encryptedDataKey[0] = 0;
			timeout = get_data_key(fc.token, fc.masterKeyId, fc.dataKeyId, fc.encryptedDataKey);
			if (timeout > 0)
			{
				memcache_set(CACHE_KEYNAME_MAKSTERKEYID, fc.masterKeyId, timeout);
				memcache_set(CACHE_KEYNAME_DATAKEYID, fc.dataKeyId, timeout);
				memcache_set(CACHE_KEYNAME_ENCRYPTEDDATAKEY, fc.encryptedDataKey, timeout);
				dktimeout = timeout;
			}
			else
			{
				goto KEY_ERROR;
			}
		}
		ret = memcache_get(CACHE_KEYNAME_MAKSTERKEYID, fc.masterKeyId);
		ret += memcache_get(CACHE_KEYNAME_DATAKEYID, fc.dataKeyId);
		ret += memcache_get(CACHE_KEYNAME_ENCRYPTEDDATAKEY, fc.encryptedDataKey);
		if (ret < 0)
		{
			goto KEY_ERROR;
		}
		
		// Master Key
		mktimeout -= 30;
		if (mktimeout <= 30)
		{
			fc.masterKey[0] = 0;
			fc.initializationVector[0] = 0;
			timeout = get_master_key(fc.token, fc.masterKeyId, fc.masterKey, fc.initializationVector);
			if (timeout > 0)
			{
				memcache_set(CACHE_KEYNAME_MAKSTERKEY, fc.masterKey, timeout);
				memcache_set(CACHE_KEYNAME_IV, fc.initializationVector, timeout);
				mktimeout = timeout;
			}
			else
			{
				goto KEY_ERROR;
			}
		}
		ret = memcache_get(CACHE_KEYNAME_MAKSTERKEY, fc.masterKey);
		ret += memcache_get(CACHE_KEYNAME_IV, fc.initializationVector);
		if (ret < 0)
		{
			goto KEY_ERROR;
		}
		
		// calculate the real key
		ret = key_calculate_real(&fc);
		if (ret == 0)
		{
			char dataKeyCacheName[KEY_SIZE];
			memset(dataKeyCacheName, 0, KEY_SIZE);
			sprintf(dataKeyCacheName, "fastcgienc-%s-%s-%s", fc.masterKeyId, fc.dataKeyId, fcgienc_username);
			memcache_set(dataKeyCacheName, fc.dataKey, KEY_STORE_PERIOD);

			if (timeout <= 0)
				timeout = KEY_STORE_PERIOD;
			memcache_set(CACHE_KEYNAME_DATAKEY, fc.dataKey, 60);
		}
		else
			goto KEY_ERROR;

#ifdef WIN32
		Sleep(30000);
#else
		sleep(30);
#endif
		continue;

KEY_ERROR:
		authtimeout = mktimeout = dktimeout = -1;
#ifdef WIN32
		Sleep(30000);
#else
		sleep(30);
#endif
	}
	
	apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

/**
 * first read the keys from key server and store into memcache
 */

int key_thread_init(void)
{
	int ret = 0;
	apr_threadattr_t *threadAttr;
	apr_status_t rv;
	apr_pool_t *threadPool = NULL;
	apr_thread_t *threadD = NULL;

	// if already inited
	if (threadD != NULL)
		return 0;
	
	// check parameters
	if (!fcgienc_username || !fcgienc_password || !fcgienc_authserver || 
		!fcgienc_masterkeyserver || !fcgienc_datakeyserver)
	{
		return -1;
	}

	// create key thread
	if (threadPool)
	{
		apr_pool_destroy(threadPool);
		threadPool = NULL;
	}

	apr_pool_create(&threadPool, NULL);
	apr_threadattr_create(&threadAttr, threadPool);
	rv = apr_thread_create(&threadD, threadAttr, key_thread_func, NULL, threadPool);
	if (rv != APR_SUCCESS)
	{
		ret = -1;
	}
	apr_thread_detach(threadD);

	return ret;
}