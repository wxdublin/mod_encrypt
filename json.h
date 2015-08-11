/*
 * Copyright (c) 2009-2014 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _JSON_H__
#define _JSON_H__

void *json_load(const char *text);
int json_get_string(void *jobject, char *key, char *value);
int json_get_integer(void *jobject, char *key, int *value);
void json_unload(void *jobject);

#endif // _JSON_H__
