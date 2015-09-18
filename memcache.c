
#include <stdlib.h>
#include "apr_memcache.h"
#include "memcache.h"
#include "fcgi.h"
#include "log.h"

static apr_pool_t *MemcachePool = NULL;
static apr_memcache_t *Memcache = NULL;

#define UNTIL	3600
int memcache_init(const char *host_name, const int port_num)
{
	apr_status_t rv;
	apr_memcache_server_t *server;
	apr_memcache_stats_t* stats;
	char *result;

	if (Memcache != NULL)
		return 0;

	if ((host_name==NULL) || port_num < 1)
		goto MEMCACHE_INIT_EXIT;

	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}
	
	apr_initialize();
	atexit(apr_terminate);
	apr_pool_create(&MemcachePool, NULL);

	rv = apr_memcache_create(MemcachePool, 10, 0, &Memcache);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_server_create(MemcachePool, host_name, port_num, 0, 1, 1, 60, &server);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_add_server(Memcache, server);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_version(server, MemcachePool, &result);
	if (rv) goto MEMCACHE_INIT_EXIT;

	rv = apr_memcache_stats(server, MemcachePool, &stats);
	if (rv) goto MEMCACHE_INIT_EXIT;

	return 0;

MEMCACHE_INIT_EXIT:
	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}
	Memcache = NULL;

	return -1;
}

int memcache_set(const char *key, const char *value)
{
	apr_status_t rv;
	if (!Memcache || !key || !value)
		return -1;
	rv = apr_memcache_set(Memcache, key, (char *)value, strlen(value), UNTIL, 0);

	return rv;
}

int memcache_set_timeout(const char *key, const char *value, unsigned int timeout)
{
	apr_status_t rv;
	if (!Memcache || !key || !value)
		return -1;
	rv = apr_memcache_set(Memcache, key, (char *)value, strlen(value), (apr_uint32_t)timeout, 0);

	return rv;
}

int memcache_get(const char *key, char *value)
{
	apr_status_t rv;
	apr_size_t len;
	char *result;

	if (!Memcache || !key)
		return -1;

	rv = apr_memcache_getp(Memcache, MemcachePool, key, &result, &len, NULL);

	if (rv == 0)
	{
		memcpy(value, result, len);
		value[len] = 0;
		return 0;
	} 
	else
	{
		return -1;
	}
}

int memcache_delete(const char *key)
{
	apr_status_t rv;
	if (!Memcache || !key)
		return -1;
	rv = apr_memcache_delete(Memcache, key, 0);

	return rv;
}

void memcache_destroy(void)
{
	if (MemcachePool != NULL)
	{
		apr_pool_destroy(MemcachePool);
		MemcachePool = NULL;
	}
}
