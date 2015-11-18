/*
 * Copyright (c) 2015 Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef _JSON_H__
#define _JSON_H__

void *json_load(const char *text);
char *json_get_string(void *jobject, char *key);
int json_get_integer(void *jobject, char *key);
void json_unload(void *jobject);

#endif // _JSON_H__
