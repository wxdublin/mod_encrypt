#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>

#include "fcgi.h"
#include "log.h"

void log_message(int log_level, const char *key_word1, const char *log_message1, const char *key_word2, const char *log_message2)
{
	char buffer[128];

	time_t rawtime;
	struct tm * timeinfo;
	char timebuf[64];
	struct timeb timer_msec;
	long long int timestamp_msec;

	apr_status_t rv;  
	apr_file_t *dest_fp = NULL; 
	apr_size_t len;

	// check parameter
	if (!fcgi_logfp || !fcgi_logpath)
		return;

	// if log_level > log level config, do not log
	if (fcgi_loglevel < log_level)
		return;

	dest_fp = fcgi_logfp;

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	strftime (timebuf, 64, "%Y-%m-%d %H:%M:%S", timeinfo);

	ftime(&timer_msec);
	timestamp_msec = (long long int) timer_msec.millitm;

	switch (log_level)
	{
	case ENCRYPT_LOG_ERROR:
		sprintf(buffer, "\n%s,%03lld [ERROR] ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_WARNING:
		sprintf(buffer, "\n%s,%03lld [WARN]  ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_INFO:
		sprintf(buffer, "\n%s,%03lld [INFO]  ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_TRACK:
		sprintf(buffer, "\n%s,%03lld [TRACK] ", timebuf, timestamp_msec);
		break;
	default:
		return;
	}

	// file operation
	len = strlen(buffer);
	rv = apr_file_write(dest_fp, buffer, &len);  
	if (rv != APR_SUCCESS) {  
		goto done;  
	}
	if (key_word1)
	{
		len = strlen(key_word1);
		rv = apr_file_write(dest_fp, key_word1, &len);  
		if (rv != APR_SUCCESS) {  
			goto done;  
		}
	}
	if (log_message1)
	{
		len = 1;
		rv = apr_file_write(dest_fp, " ", &len);  
		len = strlen(log_message1);
		rv = apr_file_write(dest_fp, log_message1, &len);  
		if (rv != APR_SUCCESS) {  
			goto done;  
		}
	}
	if (key_word2)
	{
		len = 2;
		rv = apr_file_write(dest_fp, ", ", &len);  
		len = strlen(key_word2);
		rv = apr_file_write(dest_fp, key_word2, &len);  
		if (rv != APR_SUCCESS) {  
			goto done;  
		}
	}
	if (log_message2)
	{
		len = 1;
		rv = apr_file_write(dest_fp, " ", &len);  
		len = strlen(log_message2);
		rv = apr_file_write(dest_fp, log_message2, &len);  
		if (rv != APR_SUCCESS) {  
			goto done;  
		}
	}

done:  
	return;
}