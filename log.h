/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _LOG_H__
#define _LOG_H__

#define ENCRYPT_LOG_ERROR		0
#define ENCRYPT_LOG_WARNING		1
#define ENCRYPT_LOG_INFO		2
#define ENCRYPT_LOG_TRACK		3

void log_message(int log_level, char *log_message);

#endif // _LOG_H__
