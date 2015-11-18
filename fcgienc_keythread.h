/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _FCGIENC_KEY_THREAD_H__
#define _FCGIENC_KEY_THREAD_H__

void* APR_THREAD_FUNC key_thread_func(apr_thread_t *thd, void *params);
int key_thread_init(void);

#endif // _FCGIENC_KEY_THREAD_H__
