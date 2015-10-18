
#ifndef MEMCACHE_H
#define MEMCACHE_H

/** @} */

int memcache_set(const char *key, const char *value, unsigned int timeout);
int memcache_get(const char *key, char *value);


#endif /* MEMCACHE_H */
