/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _LOG_H__
#define _LOG_H__

#define ENCRYPT_LOG_ERROR		0
#define ENCRYPT_LOG_WARNING		1
#define ENCRYPT_LOG_INFO		2
#define ENCRYPT_LOG_TRACK		3

void log_message(int log_level, const char *key_word1, const char *log_message1, const char *key_word2, const char *log_message2);

#endif // _LOG_H__
