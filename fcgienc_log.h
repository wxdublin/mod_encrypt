/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _FCGIENC_LOG_H__
#define _FCGIENC_LOG_H__

#define ENCRYPT_LOG_EMERG		0
#define ENCRYPT_LOG_ALERT		1
#define ENCRYPT_LOG_CRIT		2
#define ENCRYPT_LOG_ERR			3
#define ENCRYPT_LOG_WARN		4
#define ENCRYPT_LOG_NOTICE		5
#define ENCRYPT_LOG_INFO		6
#define ENCRYPT_LOG_DEBUG		7

void log_message(int log_level, const char *fmt, ...);

#endif // _FCGIENC_LOG_H__
