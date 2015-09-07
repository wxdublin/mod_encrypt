/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _KEY_H__
#define _KEY_H__

int key_auth_request(request_rec * r, fcgi_crypt * fc, const char *server);
int key_master_request(request_rec * r, fcgi_crypt * fc, const char *server);
int key_data_request(request_rec * r, fcgi_crypt * fc, const char *server);

#endif // _KEY_H__
