
#ifndef MEMCACHE_H
#define MEMCACHE_H

/** @} */

int memcache_set(const char *key, const char *value, unsigned int timeout);
int memcache_get(const char *key, char *value);
int memcache_init(void);
void memcache_close(void);

#endif /* MEMCACHE_H */
