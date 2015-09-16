
#ifndef MEMCACHE_H
#define MEMCACHE_H

/** @} */

int memcache_init(const char *host_name, const int port_num);
void memcache_destroy(void);
int memcache_set(const char *key, const char *value);
int memcache_set_timeout(const char *key, const char *value, unsigned int timeout);
int memcache_get(const char *key, char *value);
int memcache_delete(const char *key);


#endif /* MEMCACHE_H */
