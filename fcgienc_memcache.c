
#include <stdlib.h>
#include "apr_memcache.h"
#include "fcgienc_memcache.h"

#define UNTIL	3600

extern char *fcgienc_memcached_server;
extern unsigned short fcgienc_memcached_port;

static apr_memcache_server_t *server;
static apr_pool_t *memcachePool;
static apr_memcache_t *memcacheD = NULL;

int memcache_set(const char *key, const char *value, unsigned int timeout)
{
	apr_status_t rv;

	if (!memcacheD || !key || !value)
		return -1;

	if (timeout == 0)
		rv = apr_memcache_set(memcacheD, key, (char *)value, strlen(value), UNTIL, 0);
	else
		rv = apr_memcache_set(memcacheD, key, (char *)value, strlen(value), (apr_uint32_t)timeout, 0);

	if (rv == 0)
		return 0;

	return -1;
}

int memcache_get(const char *key, char *value)
{
	apr_status_t rv;
	apr_size_t len;
	char *result;
	apr_pool_t *pool;

	if (!memcacheD || !key)
		return -1;

	apr_pool_create(&pool, NULL);
	rv = apr_memcache_getp(memcacheD, pool, key, &result, &len, NULL);
	apr_pool_destroy(pool);

	if (rv == 0)
	{
		memcpy(value, result, len);
		value[len] = 0;
		return 0;
	}

	return -1;
}

int memcache_init(void)
{
	apr_status_t rv;

	if ((fcgienc_memcached_server==NULL) || fcgienc_memcached_port < 1)
		return -1;

	apr_initialize();
	atexit(apr_terminate);
	apr_pool_create(&memcachePool, NULL);

	rv = apr_memcache_create(memcachePool, 10, 0, &memcacheD);
	if (rv) 
		goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_server_create(memcachePool, fcgienc_memcached_server, fcgienc_memcached_port, 0, 1, 1, 60, &server);
	if (rv) 
		goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_add_server(memcacheD, server);
	if (rv) 
		goto MEMCACHE_INIT_EXIT;

	return 0;

MEMCACHE_INIT_EXIT:
	return -1;
}

void memcache_close(void)
{
	if(memcachePool)
		apr_pool_destroy(memcachePool);

	memcachePool = NULL;
}