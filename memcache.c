
#include <stdlib.h>
#include "apr_memcache.h"
#include "memcache.h"
#include "fcgi.h"
#include "log.h"

#define UNTIL	3600

int memcache_set(const char *key, const char *value, unsigned int timeout)
{
	apr_status_t rv;
	apr_memcache_server_t *server;
	apr_memcache_stats_t* stats;
	apr_pool_t *memcachePool = NULL;
	apr_memcache_t *memcacheD = NULL;
	char *result;

	if ((fcgi_memcached_server==NULL) || fcgi_memcached_port < 1)
		return -1;

	apr_initialize();
	atexit(apr_terminate);
	apr_pool_create(&memcachePool, NULL);

	rv = apr_memcache_create(memcachePool, 10, 0, &memcacheD);
	if (rv) 
		goto MEMCACHE_SET_EXIT;

	rv = apr_memcache_server_create(memcachePool, fcgi_memcached_server, fcgi_memcached_port, 0, 1, 1, 60, &server);
	if (rv) 
		goto MEMCACHE_SET_EXIT;

	rv = apr_memcache_add_server(memcacheD, server);
	if (rv) 
		goto MEMCACHE_SET_EXIT;

	rv = apr_memcache_version(server, memcachePool, &result);
	if (rv) 
		goto MEMCACHE_SET_EXIT;

	rv = apr_memcache_stats(server, memcachePool, &stats);
	if (rv) 
		goto MEMCACHE_SET_EXIT;

	if (!memcacheD || !key || !value)
		goto MEMCACHE_SET_EXIT;

	if (timeout == 0)
		rv = apr_memcache_set(memcacheD, key, (char *)value, strlen(value), UNTIL, 0);
	else
		rv = apr_memcache_set(memcacheD, key, (char *)value, strlen(value), (apr_uint32_t)timeout, 0);

	apr_pool_destroy(memcachePool);

	return rv;

MEMCACHE_SET_EXIT:
	if (memcachePool != NULL)
	{
		apr_pool_destroy(memcachePool);
		memcachePool = NULL;
	}
	memcacheD = NULL;

	return -1;
}

int memcache_get(const char *key, char *value)
{
	apr_status_t rv;
	apr_size_t len;
	apr_memcache_server_t *server;
	apr_memcache_stats_t* stats;
	apr_pool_t *memcachePool = NULL;
	apr_memcache_t *memcacheD = NULL;
	char *result;

	if ((fcgi_memcached_server==NULL) || fcgi_memcached_port < 1)
		return -1;

	apr_initialize();
	atexit(apr_terminate);
	apr_pool_create(&memcachePool, NULL);

	rv = apr_memcache_create(memcachePool, 10, 0, &memcacheD);
	if (rv) 
		goto MEMCACHE_GET_EXIT;

	rv = apr_memcache_server_create(memcachePool, fcgi_memcached_server, fcgi_memcached_port, 0, 1, 1, 60, &server);
	if (rv) 
		goto MEMCACHE_GET_EXIT;

	rv = apr_memcache_add_server(memcacheD, server);
	if (rv) 
		goto MEMCACHE_GET_EXIT;

	rv = apr_memcache_version(server, memcachePool, &result);
	if (rv) 
		goto MEMCACHE_GET_EXIT;

	rv = apr_memcache_stats(server, memcachePool, &stats);
	if (rv) 
		goto MEMCACHE_GET_EXIT;

	if (!memcacheD || !key)
		return -1;

	rv = apr_memcache_getp(memcacheD, memcachePool, key, &result, &len, NULL);

	if (rv == 0)
	{
		memcpy(value, result, len);
		value[len] = 0;
	} 

	apr_pool_destroy(memcachePool);

	return rv;

MEMCACHE_GET_EXIT:
	if (memcachePool != NULL)
	{
		apr_pool_destroy(memcachePool);
		memcachePool = NULL;
	}
	memcacheD = NULL;

	return -1;
}

