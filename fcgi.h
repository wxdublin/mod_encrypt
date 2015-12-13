/*
 * $Id: fcgienc.h,v 1.47 2007/09/23 16:33:29 robs Exp $
 */

#ifndef FCGI_H
#define FCGI_H

#if defined(DEBUG) && ! defined(NDEBUG)
#define ASSERT(a) ap_assert(a)
#else
#define ASSERT(a) ((void) 0)
#endif

#ifdef WIN32
/* warning C4115: named type definition in parentheses */
#pragma warning(disable : 4115)
/* warning C4514: unreferenced inline function has been removed */
#pragma warning(disable:4514)
/* warning C4244: conversion from 64 to 32 has been removed */
#pragma warning(disable:4244)
/* warning C4267: conversion from size_t to 32 has been removed */
#pragma warning(disable:4267)
#endif

/* Apache header files */
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "util_md5.h"

/* AP2TODO there's probably a better way */
#ifdef STANDARD20_MODULE_STUFF
#define APACHE2
#endif

#ifdef APACHE2

#include <sys/stat.h>
#include "ap_compat.h"
#include "apr_strings.h"

typedef struct apr_array_header_t array_header;
typedef struct apr_table_t table;
typedef struct apr_pool_t pool;
#define NET_SIZE_T apr_socklen_t 

#ifndef BOOL
typedef int BOOL;
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef apr_status_t apcb_t;
#define APCB_OK APR_SUCCESS

#define XtOffsetOf APR_OFFSETOF
#define ap_select select

#if MODULE_MAGIC_NUMBER > 20081201
#define ap_user_id        ap_unixd_config.user_id
#define ap_group_id       ap_unixd_config.group_id
#define ap_user_name      ap_unixd_config.user_name
#define ap_suexec_enabled ap_unixd_config.suexec_enabled
#else
#define ap_user_id        unixd_config.user_id
#define ap_group_id       unixd_config.group_id
#define ap_user_name      unixd_config.user_name
#define ap_suexec_enabled unixd_config.suexec_enabled
#endif

#ifndef S_ISDIR
#define S_ISDIR(m)      (((m)&(S_IFMT)) == (S_IFDIR))
#endif

/* obsolete fns */
#define ap_hard_timeout(a,b)
#define ap_kill_timeout(a)
#define ap_block_alarms()
#define ap_reset_timeout(a)
#define ap_unblock_alarms()

/* starting with apache 2.2 the backward-compatibility defines for
 * 1.3 APIs are not available anymore. Define them ourselves here.
 */
#ifndef ap_copy_table

#define ap_copy_table apr_table_copy
#define ap_cpystrn apr_cpystrn
#define ap_destroy_pool apr_pool_destroy
#define ap_isspace apr_isspace
#define ap_make_array apr_array_make
#define ap_make_table apr_table_make
#define ap_null_cleanup apr_pool_cleanup_null
#define ap_palloc apr_palloc
#define ap_pcalloc apr_pcalloc
#define ap_psprintf apr_psprintf
#define ap_pstrcat apr_pstrcat
#define ap_pstrdup apr_pstrdup
#define ap_pstrndup apr_pstrndup
#define ap_push_array apr_array_push
#define ap_register_cleanup apr_pool_cleanup_register
#define ap_snprintf apr_snprintf
#define ap_table_add apr_table_add
#define ap_table_do apr_table_do
#define ap_table_get apr_table_get
#define ap_table_set apr_table_set
#define ap_table_setn apr_table_setn
#define ap_table_unset apr_table_unset

#endif /* defined(ap_copy_table) */

#if (defined(HAVE_WRITEV) && !HAVE_WRITEV && !defined(NO_WRITEV)) || defined WIN32
#define NO_WRITEV
#endif

#else /* !APACHE2 */

#include "http_conf_globals.h"
typedef void apcb_t;
#define APCB_OK 

#endif /* !APACHE2 */

#ifndef NO_WRITEV 
#include <sys/uio.h>
#endif

#ifdef WIN32
#ifndef APACHE2
#include "multithread.h"
#endif
#pragma warning(default : 4115)
#else
#include <sys/un.h>
#endif

#endif  /* FCGIENC_H */

