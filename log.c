#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>

#include "fcgi.h"
#include "log.h"

void log_message(int log_level, char *log_message)
{
	char buffer [512];

	time_t rawtime;
	struct tm * timeinfo;
	char timebuf[64];
	struct timeb timer_msec;
	long long int timestamp_msec;

	apr_status_t rv;  
	apr_pool_t *mp; 
	apr_file_t *dest_fp = NULL; 
	apr_size_t len;
	char errbuf [512];

	// check parameter
	if (!fcgi_logpath || !log_message)
		return;

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	strftime (timebuf, 64, "%Y-%m-%d %H:%M:%S", timeinfo);

	ftime(&timer_msec);
	timestamp_msec = (long long int) timer_msec.millitm;

	switch (log_level)
	{
	case ENCRYPT_LOG_ERROR:
		sprintf(buffer, "%s,%03lld [ERROR] %s\n", timebuf, timestamp_msec, log_message);
		break;
	case ENCRYPT_LOG_WARNING:
		sprintf(buffer, "%s,%03lld [WARN]  %s\n", timebuf, timestamp_msec, log_message);
		break;
	case ENCRYPT_LOG_INFO:
		sprintf(buffer, "%s,%03lld [INFO]  %s\n", timebuf, timestamp_msec, log_message);
		break;
	case ENCRYPT_LOG_TRACK:
		sprintf(buffer, "%s,%03lld [TRACK] %s\n", timebuf, timestamp_msec, log_message);
		break;
	default:
		sprintf(buffer, "%s,%03lld [UNKNOWN]\n", timebuf, timestamp_msec);
		break;
	}

	// file operation
	apr_initialize();  
	apr_pool_create(&mp, NULL); 

	if ((rv = apr_file_open(&dest_fp, fcgi_logpath, \
			APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_APPEND | APR_FOPEN_XTHREAD | 0, \
			APR_OS_DEFAULT, mp)) != APR_SUCCESS) {  
		apr_strerror(rv, errbuf, sizeof(errbuf));
		goto done;  
	}

	len = strlen(buffer);
	rv = apr_file_write(dest_fp, buffer, &len);  
	if (rv != APR_SUCCESS) {  
		goto done;  
	}

done:  
	if (dest_fp) {  
		apr_file_close(dest_fp);  
	}
	apr_pool_destroy(mp);  
	apr_terminate();  
	return;
}