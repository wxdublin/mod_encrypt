#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>

#include "fcgi.h"
#include "log.h"

void log_message(int log_level, const char *fmt, ...)
{
	va_list ap;
	char headbuffer[128];
	char msgbuffer[4096];

	time_t rawtime;
	struct tm * timeinfo;
	char timebuf[64];
	struct timeb timer_msec;
	long long int timestamp_msec;
	apr_file_t *dest_fp = NULL; 

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
	case ENCRYPT_LOG_EMERG:
		sprintf(headbuffer, "\n%s,%03lld [EMERG] ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_ALERT:
		sprintf(headbuffer, "\n%s,%03lld [ALERT] ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_CRIT:
		sprintf(headbuffer, "\n%s,%03lld [CRIT]  ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_ERR:
		sprintf(headbuffer, "\n%s,%03lld [ERROR] ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_WARN:
		sprintf(headbuffer, "\n%s,%03lld [WARN]  ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_NOTICE:
		sprintf(headbuffer, "\n%s,%03lld [NOTICE]", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_INFO:
		sprintf(headbuffer, "\n%s,%03lld [INFO]  ", timebuf, timestamp_msec);
		break;
	case ENCRYPT_LOG_DEBUG:
		sprintf(headbuffer, "\n%s,%03lld [DEBUG] ", timebuf, timestamp_msec);
		break;
	default:
		return;
	}
	
	va_start(ap, fmt);
	vsprintf(msgbuffer, fmt, ap);
	va_end(ap);

	// file operation
	apr_file_printf(dest_fp, "%s %s", headbuffer, msgbuffer);
	
	

	return;
}