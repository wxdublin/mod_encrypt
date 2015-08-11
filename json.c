#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

/*
 * Parse text into a JSON object. If text is valid JSON, returns a
 * json_t structure, otherwise prints and error and returns null.
 */
void *json_load(const char *text)
{
    json_t *root;
    json_error_t error;

    root = json_loads(text, 0, &error);

    if (root) {
        return (void *)root;
    } else {
        return NULL;
    }
}

int json_get_string(void *jobject, char *key, char *value)
{
	const json_t *jroot;
	const char *ret;

	if (!jobject || !key || !value)
		return -1;

	jroot = (const json_t *)jobject;

	ret = json_string_value(json_object_get(jroot, key));
	if (!ret)
		return -1;

	strcpy(value, ret);

	return 0;
}

int json_get_integer(void *jobject, char *key, int *value)
{
	const json_t *jroot;
	json_int_t ret;

	if (!jobject || !key || !value)
		return -1;

	jroot = (const json_t *)jobject;

	ret = json_integer_value(json_object_get(jroot, key));
	if (!ret)
		return -1;

	*value = (int)ret;

	return 0;
}

void json_unload(void *jobject)
{
	json_t *jroot;

	if (!jobject)
		return;

	jroot = (json_t *)jobject;

	json_decref(jroot);

	return;
}