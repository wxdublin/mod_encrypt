/*
 * $Id: fcgienc.h,v 1.47 2007/09/23 16:33:29 robs Exp $
 */

#ifndef FCGIENC_H
#define FCGIENC_H

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

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(encrypt);
#endif

/* AP2TODO there's probably a better way */
#ifdef STANDARD20_MODULE_STUFF
#define APACHE2
#endif

#ifdef APACHE2

#include <sys/stat.h>
#include "ap_compat.h"
#include "apr_strings.h"

#ifdef WIN32
#if MODULE_MAGIC_NUMBER < 20020903
#error "mod_encrypt is incompatible with Apache versions older than 2.0.41 under WIN"
#endif
#endif

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

#if MODULE_MAGIC_NUMBER < 19990320
#error "This version of mod_encrypt is incompatible with Apache versions older than 1.3.6."
#endif

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

/* FastCGIENC header files */
#include "mod_encrypt.h"
/* @@@ This should go away when fcgienc_protocol is re-written */
#include "fcgienc_protocol.h"

typedef struct {
    int size;               /* size of entire buffer */
    int length;             /* number of bytes in current buffer */
    char *begin;            /* begining of valid data */
    char *end;              /* end of valid data */
    char data[1];           /* buffer data */
} Buffer;

#ifdef WIN32
#define READER 0
#define WRITER 1

#define MBOX_EVENT 0   /* mboc is ready to be read */
#define TERM_EVENT 1   /* termination event */
#define WAKE_EVENT 2   /* notification of child Fserver dieing */

typedef struct _fcgienc_pm_job {
    char id;
    char *fs_path;
    char *user;
    char * group;
    unsigned long qsec;
    unsigned long start_time;
    struct _fcgienc_pm_job *next;
} fcgienc_pm_job;
#endif

enum process_state { 
    FCGIENC_RUNNING_STATE,             /* currently running */
    FCGIENC_START_STATE,               /* needs to be started by PM */
    FCGIENC_VICTIM_STATE,              /* SIGTERM was sent by PM */
    FCGIENC_KILLED_STATE,              /* a wait() collected VICTIM */
    FCGIENC_READY_STATE                /* empty cell, init state */
};

/*
 * ServerProcess holds data for each process associated with
 * a class.  It is embedded in fcgienc_server below.
 */
typedef struct _FcgiProcessInfo {
#ifdef WIN32
    HANDLE handle;                   /* process handle */
    HANDLE terminationEvent;         /* Event used to signal process termination */
#endif
    pid_t pid;                       /* pid of associated process */
    enum process_state state;        /* state of the process */
    time_t start_time;               /* time the process was started */
} ServerProcess;

/*
 * fcgienc_server holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiEncServerInfo {
    int flush;
    char *fs_path;                  /* pathname of executable */
    array_header *pass_headers;     /* names of headers to pass in the env */
    u_int idle_timeout;             /* fs idle secs allowed before aborting */
    char **envp;                    /* if NOT NULL, this is the env to send
                                     * to the fcgi app when starting a server
                                     * managed app. */
    u_int listenQueueDepth;         /* size of listen queue for IPC */
    u_int appConnectTimeout;        /* timeout (sec) for connect() requests */
    u_int numProcesses;             /* max allowed processes of this class,
                                     * or for dynamic apps, the number of
                                     * processes actually running */
    time_t startTime;               /* the time the application was started */
    time_t restartTime;             /* most recent time when the process
                                     * manager started a process in this
                                     * class. */
    int initStartDelay;             /* min number of seconds to wait between
                                     * starting of AppClass processes at init */
    u_int restartDelay;             /* number of seconds to wait between
                                     * restarts after failure.  Can be zero. */
    u_int minServerLife;            /* minimum number of seconds a server must
                                     * live before it's considered borked. */
    int restartOnExit;              /* = TRUE = restart. else terminate/free */
    u_int numFailures;              /* num restarts due to exit failure */
    int bad;                        /* is [not] having start problems */
    struct sockaddr *socket_addr;   /* Socket Address of FCGI app server class */
#ifdef WIN32
    struct sockaddr *dest_addr;     /* for local apps on NT need socket address */
                                    /* bound to localhost */
    const char *mutex_env_string;   /* string holding the accept mutex handle */
#endif
    int socket_addr_len;            /* Length of socket */
    enum {APP_CLASS_UNKNOWN,
          APP_CLASS_STANDARD,
          APP_CLASS_EXTERNAL,
          APP_CLASS_DYNAMIC}
         directive;                 /* AppClass or ExternalAppClass */
    const char *socket_path;        /* Name used to create a socket */
    const char *host;               /* Hostname for externally managed
                                     * FastCGIENC application processes */
    unsigned short port;            /* Port number either for externally
                                     * managed FastCGIENC applications or for
                                     * server managed FastCGIENC applications,
                                     * where server became application mngr. */
    int listenFd;                   /* Listener socket of FCGI app server
                                     * class.  Passed to app server process
                                     * at process creation. */
    u_int processPriority;          /* If locally server managed process,
                                     * this is the priority to run the
                                     * processes in this class at. */
    struct _FcgiProcessInfo *procs; /* Pointer to array of
                                     * processes belonging to this class. */
    int keepConnection;             /* = 1 = maintain connection to app. */
    uid_t uid;                      /* uid this app should run as (suexec) */
    gid_t gid;                      /* gid this app should run as (suexec) */
    const char *username;           /* suexec user arg */
    const char *group;              /* suexec group arg, AND used in comm
                                     * between RH and PM */
    const char *user;               /* used in comm between RH and PM */
    /* Dynamic FastCGIENC apps configuration parameters */
    u_long totalConnTime;           /* microseconds spent by the web server
                                     * waiting while encrypt app performs
                                     * request processing since the last
                                     * dynamicUpdateInterval */
    u_long smoothConnTime;          /* exponentially decayed values of the
                                     * connection times. */
    u_long totalQueueTime;          /* microseconds spent by the web server
                                     * waiting to connect to the encrypt app
                                     * since the last dynamicUpdateInterval. */
    int nph;
    struct _FastCgiEncServerInfo *next;
} fcgienc_server;

/*
 * fcgi_request holds the state of a particular Encrypt request.
 */
typedef struct {
	void *crypt;
	int offset;

	char token[256];
	char masterKeyId[256];
	char masterKey[256];
	char initializationVector[256];
	char dataKeyId[256];
	char encryptedDataKey[256];
	char dataKey[256];
	int dataKeyLength;
} fcgienc_crypt;

/*
 * fcgienc_request holds the state of a particular FastCGIENC request.
 */
typedef struct {
#ifdef WIN32
    SOCKET fd;
#else
    int fd;                         /* connection to FastCGIENC server */
#endif
    int gotHeader;                  /* TRUE if reading content bytes */
    unsigned char packetType;       /* type of packet */
    int dataLen;                    /* length of data bytes */
    int paddingLen;                 /* record padding after content */
    fcgienc_server *fs;                /* FastCGIENC server info */
    const char *fs_path;         /* fcgienc_server path */
    Buffer *serverInputBuffer;   /* input buffer from FastCgiEnc server */
    Buffer *serverOutputBuffer;  /* output buffer to FastCgiEnc server */
    Buffer *clientInputBuffer;   /* client input buffer */
    Buffer *clientOutputBuffer;  /* client output buffer */
    table *authHeaders;          /* headers received from an auth fs */
    int auth_compat;             /* whether the auth request is spec compat */
    table *saved_subprocess_env; /* subprocess_env before auth handling */
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    array_header *header;
    char *fs_stderr;
    int fs_stderr_len;
    int parseHeader;                /* TRUE iff parsing response headers */
    request_rec *r;
    int readingEndRequestBody;
    FCGIENC_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    unsigned int requestId;
    int eofSent;
    int role;                       /* FastCGIENC Role: Authorizer or Responder */
    int dynamic;                    /* whether or not this is a dynamic app */
    struct timeval startTime;       /* dynamic app's connect() attempt start time */
    struct timeval queueTime;       /* dynamic app's connect() complete time */
    struct timeval completeTime;    /* dynamic app's connection close() time */
    int keepReadingFromFcgiApp;     /* still more to read from fcgi app? */
    const char *user;               /* user used to invoke app (suexec) */
    const char *group;              /* group used to invoke app (suexec) */
#ifdef WIN32
    BOOL using_npipe_io;             /* named pipe io */
#endif
    int nph;

	fcgienc_crypt encryptor;
	fcgienc_crypt decryptor;
} fcgienc_request;

/* Values of parseHeader field */
#define SCAN_CGI_READING_HEADERS 1
#define SCAN_CGI_FINISHED        0
#define SCAN_CGI_BAD_HEADER     -1
#define SCAN_CGI_INT_REDIRECT   -2
#define SCAN_CGI_SRV_REDIRECT   -3

/* Opcodes for Server->ProcMgr communication */
#define FCGIENC_SERVER_START_JOB     83        /* 'S' - start */
#define FCGIENC_SERVER_RESTART_JOB   82        /* 'R' - restart */
#define FCGIENC_REQUEST_TIMEOUT_JOB  84        /* 'T' - timeout */
#define FCGIENC_REQUEST_COMPLETE_JOB 67        /* 'C' - complete */

/* Authorizer types, for auth directives handling */
#define FCGIENC_AUTH_TYPE_AUTHENTICATOR  0
#define FCGIENC_AUTH_TYPE_AUTHORIZER     1
#define FCGIENC_AUTH_TYPE_ACCESS_CHECKER 2

/* Bits for auth_options */
#define FCGIENC_AUTHORITATIVE 1
#define FCGIENC_COMPAT 2

typedef struct
{
    const char *authorizer;
    u_char authorizer_options;
    const char *authenticator;
    u_char authenticator_options;
    const char *access_checker;
    u_char access_checker_options;
} fcgienc_dir_config;

#define FCGIENC_OK     0
#define FCGIENC_FAILED 1

#ifdef APACHE2

#ifdef WIN32
#define FCGIENC_LOG_EMERG          APLOG_MARK,APLOG_EMERG,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_ALERT          APLOG_MARK,APLOG_ALERT,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_CRIT           APLOG_MARK,APLOG_CRIT,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_ERR            APLOG_MARK,APLOG_ERR,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_WARN           APLOG_MARK,APLOG_WARNING,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_NOTICE         APLOG_MARK,APLOG_NOTICE,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_INFO           APLOG_MARK,APLOG_INFO,APR_FROM_OS_ERROR(GetLastError())
#define FCGIENC_LOG_DEBUG          APLOG_MARK,APLOG_DEBUG,APR_FROM_OS_ERROR(GetLastError())
#else /* !WIN32 */
#define FCGIENC_LOG_EMERG          APLOG_MARK,APLOG_EMERG,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_ALERT          APLOG_MARK,APLOG_ALERT,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_CRIT           APLOG_MARK,APLOG_CRIT,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_ERR            APLOG_MARK,APLOG_ERR,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_WARN           APLOG_MARK,APLOG_WARNING,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_NOTICE         APLOG_MARK,APLOG_NOTICE,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_INFO           APLOG_MARK,APLOG_INFO,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_DEBUG          APLOG_MARK,APLOG_DEBUG,APR_FROM_OS_ERROR(errno)
#endif

#define FCGIENC_LOG_EMERG_ERRNO    APLOG_MARK,APLOG_EMERG,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_ALERT_ERRNO    APLOG_MARK,APLOG_ALERT,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_CRIT_ERRNO     APLOG_MARK,APLOG_CRIT,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_ERR_ERRNO      APLOG_MARK,APLOG_ERR,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_WARN_ERRNO     APLOG_MARK,APLOG_WARNING,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_NOTICE_ERRNO   APLOG_MARK,APLOG_NOTICE,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_INFO_ERRNO     APLOG_MARK,APLOG_INFO,APR_FROM_OS_ERROR(errno)
#define FCGIENC_LOG_DEBUG_ERRNO    APLOG_MARK,APLOG_DEBUG,APR_FROM_OS_ERROR(errno)

#define FCGIENC_LOG_EMERG_NOERRNO    APLOG_MARK,APLOG_EMERG,0
#define FCGIENC_LOG_ALERT_NOERRNO    APLOG_MARK,APLOG_ALERT,0
#define FCGIENC_LOG_CRIT_NOERRNO     APLOG_MARK,APLOG_CRIT,0
#define FCGIENC_LOG_ERR_NOERRNO      APLOG_MARK,APLOG_ERR,0
#define FCGIENC_LOG_WARN_NOERRNO     APLOG_MARK,APLOG_WARNING,0
#define FCGIENC_LOG_NOTICE_NOERRNO   APLOG_MARK,APLOG_NOTICE,0
#define FCGIENC_LOG_INFO_NOERRNO     APLOG_MARK,APLOG_INFO,0
#define FCGIENC_LOG_DEBUG_NOERRNO    APLOG_MARK,APLOG_DEBUG,0

#else /* !APACHE2 */

#ifdef WIN32
#define FCGIENC_LOG_EMERG          APLOG_MARK,APLOG_EMERG|APLOG_WIN32ERROR
#define FCGIENC_LOG_ALERT          APLOG_MARK,APLOG_ALERT|APLOG_WIN32ERROR
#define FCGIENC_LOG_CRIT           APLOG_MARK,APLOG_CRIT|APLOG_WIN32ERROR
#define FCGIENC_LOG_ERR            APLOG_MARK,APLOG_ERR|APLOG_WIN32ERROR
#define FCGIENC_LOG_WARN           APLOG_MARK,APLOG_WARNING|APLOG_WIN32ERROR
#define FCGIENC_LOG_NOTICE         APLOG_MARK,APLOG_NOTICE|APLOG_WIN32ERROR
#define FCGIENC_LOG_INFO           APLOG_MARK,APLOG_INFO|APLOG_WIN32ERROR
#define FCGIENC_LOG_DEBUG          APLOG_MARK,APLOG_DEBUG|APLOG_WIN32ERROR
#else /* !WIN32 */
#define FCGIENC_LOG_EMERG          APLOG_MARK,APLOG_EMERG
#define FCGIENC_LOG_ALERT          APLOG_MARK,APLOG_ALERT
#define FCGIENC_LOG_CRIT           APLOG_MARK,APLOG_CRIT
#define FCGIENC_LOG_ERR            APLOG_MARK,APLOG_ERR
#define FCGIENC_LOG_WARN           APLOG_MARK,APLOG_WARNING
#define FCGIENC_LOG_NOTICE         APLOG_MARK,APLOG_NOTICE
#define FCGIENC_LOG_INFO           APLOG_MARK,APLOG_INFO
#define FCGIENC_LOG_DEBUG          APLOG_MARK,APLOG_DEBUG
#endif

#define FCGIENC_LOG_EMERG_ERRNO    APLOG_MARK,APLOG_EMERG     /* system is unusable */
#define FCGIENC_LOG_ALERT_ERRNO    APLOG_MARK,APLOG_ALERT     /* action must be taken immediately */
#define FCGIENC_LOG_CRIT_ERRNO     APLOG_MARK,APLOG_CRIT      /* critical conditions */
#define FCGIENC_LOG_ERR_ERRNO      APLOG_MARK,APLOG_ERR       /* error conditions */
#define FCGIENC_LOG_WARN_ERRNO     APLOG_MARK,APLOG_WARNING   /* warning conditions */
#define FCGIENC_LOG_NOTICE_ERRNO   APLOG_MARK,APLOG_NOTICE    /* normal but significant condition */
#define FCGIENC_LOG_INFO_ERRNO     APLOG_MARK,APLOG_INFO      /* informational */
#define FCGIENC_LOG_DEBUG_ERRNO    APLOG_MARK,APLOG_DEBUG     /* debug-level messages */

#define FCGIENC_LOG_EMERG_NOERRNO    APLOG_MARK,APLOG_EMERG|APLOG_NOERRNO
#define FCGIENC_LOG_ALERT_NOERRNO    APLOG_MARK,APLOG_ALERT|APLOG_NOERRNO
#define FCGIENC_LOG_CRIT_NOERRNO     APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO
#define FCGIENC_LOG_ERR_NOERRNO      APLOG_MARK,APLOG_ERR|APLOG_NOERRNO
#define FCGIENC_LOG_WARN_NOERRNO     APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO
#define FCGIENC_LOG_NOTICE_NOERRNO   APLOG_MARK,APLOG_NOTICE|APLOG_NOERRNO
#define FCGIENC_LOG_INFO_NOERRNO     APLOG_MARK,APLOG_INFO|APLOG_NOERRNO
#define FCGIENC_LOG_DEBUG_NOERRNO    APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO

#endif /* !APACHE2 */

#ifdef FCGIENC_DEBUG
#define FCGIDBG1(a)              ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a);
#define FCGIDBG2(a,b)            ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b);
#define FCGIDBG3(a,b,c)          ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b,c);
#define FCGIDBG4(a,b,c,d)        ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b,c,d);
#define FCGIDBG5(a,b,c,d,e)      ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b,c,d,e);
#define FCGIDBG6(a,b,c,d,e,f)    ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b,c,d,e,f);
#define FCGIDBG7(a,b,c,d,e,f,g)  ap_log_error(FCGIENC_LOG_DEBUG,fcgienc_apache_main_server,a,b,c,d,e,f,g);
#else
#define FCGIDBG1(a)
#define FCGIDBG2(a,b)
#define FCGIDBG3(a,b,c)
#define FCGIDBG4(a,b,c,d)
#define FCGIDBG5(a,b,c,d,e)
#define FCGIDBG6(a,b,c,d,e,f)
#define FCGIDBG7(a,b,c,d,e,f,g)
#endif

/*
 * Holds the status of the sending of the environment.
 * A quick hack to dump the static vars for the NT port.
 */
typedef struct {
    enum { PREP, HEADER, NAME, VALUE } pass;
    char **envp; 
    int headerLen, nameLen, valueLen, totalLen;
    char *equalPtr;
    unsigned char headerBuff[8];
} env_status;

/*
 * fcgienc_config.c
 */
void *fcgienc_config_create_dir_config(pool *p, char *dummy);
const char *fcgienc_config_make_logfile(pool *tp, char *path);
const char *fcgienc_config_make_dir(pool *tp, char *path);
const char *fcgienc_config_make_dynamic_dir(pool *p, const int wax);
const char *fcgienc_config_new_static_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_config(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_fcgienc_uid_n_gid(int set);

const char *fcgienc_config_new_auth_server(cmd_parms * cmd,
    void *dir_config, const char *fs_path, const char * compat);

const char *fcgienc_config_set_authoritative_slot(cmd_parms * cmd,
    void * dir_config, int arg);
const char *fcgienc_config_set_socket_dir(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_wrapper(cmd_parms *cmd, void *dummy, const char *arg);
apcb_t fcgienc_config_reset_globals(void * dummy);
const char *fcgienc_config_set_env_var(pool *p, char **envp, unsigned int *envc, char * var);

const char *fcgienc_config_set_logpath(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2);
const char *fcgienc_config_set_memcached(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_encrypt(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_decrypt(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_authserver(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_masterkeyserver(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_datakeyserver(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_keystring(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_username(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgienc_config_set_password(cmd_parms *cmd, void *dummy, const char *arg);


/*
 * fcgienc_pm.c
 */
#if defined(WIN32) || defined(APACHE2)
void fcgienc_pm_main(void *dummy);
#else
int fcgienc_pm_main(void *dummy, child_info *info);
#endif

/*
 * fcgienc_protocol.c
 */
void fcgienc_protocol_queue_begin_request(fcgienc_request *fr);
void fcgienc_protocol_queue_client_buffer(fcgienc_request *fr);
int fcgienc_protocol_queue_env(request_rec *r, fcgienc_request *fr, env_status *env);
int fcgienc_protocol_dequeue(pool *p, fcgienc_request *fr);

/*
 * fcgienc_buf.c
 */
#define BufferLength(b)     ((b)->length)
#define BufferFree(b)       ((b)->size - (b)->length)

void fcgienc_buf_reset(Buffer *bufPtr);
Buffer *fcgienc_buf_new(pool *p, int size);

#ifndef WIN32
typedef int SOCKET;
#endif

int fcgienc_buf_socket_recv(Buffer *b, SOCKET socket);
int fcgienc_buf_socket_send(Buffer *b, SOCKET socket);

void fcgienc_buf_added(Buffer * const b, const unsigned int len);
void fcgienc_buf_removed(Buffer * const b, unsigned int len);
void fcgienc_buf_get_block_info(Buffer *bufPtr, char **beginPtr, int *countPtr);
void fcgienc_buf_toss(Buffer *bufPtr, int count);
void fcgienc_buf_get_free_block_info(Buffer *bufPtr, char **endPtr, int *countPtr);
void fcgienc_buf_add_update(Buffer *bufPtr, int count);
int fcgienc_buf_add_block(Buffer *bufPtr, char *data, int datalen);
int fcgienc_buf_add_string(Buffer *bufPtr, char *str);
int fcgienc_buf_get_to_block(Buffer *bufPtr, char *data, int datalen);
void fcgienc_buf_get_to_buf(Buffer *toPtr, Buffer *fromPtr, int len);
void fcgienc_buf_get_to_array(Buffer *buf, array_header *arr, int len);

/*
 * fcgienc_util.c
 */

char *fcgienc_util_socket_hash_filename(pool *p, const char *path,
    const char *user, const char *group);
const char *fcgienc_util_socket_make_path_absolute(pool * const p,
    const char *const file, const int dynamic);
#ifndef WIN32
const char *fcgienc_util_socket_make_domain_addr(pool *p, struct sockaddr_un **socket_addr,
    int *socket_addr_len, const char *socket_path);
#endif
const char *fcgienc_util_socket_make_inet_addr(pool *p, struct sockaddr_in **socket_addr,
    int *socket_addr_len, const char *host, unsigned short port);
const char *fcgienc_util_check_access(pool *tp,
    const char * const path, const struct stat *statBuf,
    const int mode, const uid_t uid, const gid_t gid);
fcgienc_server *fcgienc_util_fs_get_by_id(const char *ePath, uid_t uid, gid_t gid);
fcgienc_server *fcgienc_util_fs_get(const char *ePath, const char *user, const char *group);
const char *fcgienc_util_fs_is_path_ok(pool * const p, const char * const fs_path, struct stat *finfo);
fcgienc_server *fcgienc_util_fs_new(pool *p);
void fcgienc_util_fs_add(fcgienc_server *s);
const char *fcgienc_util_fs_set_uid_n_gid(pool *p, fcgienc_server *s, uid_t uid, gid_t gid);
ServerProcess *fcgienc_util_fs_create_procs(pool *p, int num);

int fcgienc_util_ticks(struct timeval *);

#ifdef WIN32
int fcgienc_pm_add_job(fcgienc_pm_job *new_job);
#endif

uid_t fcgienc_util_get_server_uid(const server_rec * const s);
gid_t fcgienc_util_get_server_gid(const server_rec * const s);

/*
 * Globals
 */

extern pool *fcgienc_config_pool;

extern server_rec *fcgienc_apache_main_server;

extern const char *fcgienc_wrapper;                 /* wrapper path */
extern uid_t fcgienc_user_id;                       /* the run uid of Apache & PM */
extern gid_t fcgienc_group_id;                      /* the run gid of Apache & PM */

extern fcgienc_server *fcgienc_servers;

extern char *fcgienc_socket_dir;             /* default FastCgiEncIpcDir */

/* pipe used for comm between the request handlers and the PM */
extern int fcgienc_pm_pipe[];

extern pid_t fcgienc_pm_pid;

extern char *fcgienc_dynamic_dir;            /* directory for the dynamic
                                           * encrypt apps' sockets */

extern char *fcgienc_empty_env;

extern int fcgienc_dynamic_total_proc_count;
extern time_t fcgienc_dynamic_epoch;
extern time_t fcgienc_dynamic_last_analyzed;

#ifdef WIN32
extern HANDLE *fcgienc_dynamic_mbox_mutex;
extern HANDLE fcgienc_event_handles[3];
extern fcgienc_pm_job *fcgienc_dynamic_mbox;
#endif

extern u_int dynamicMaxProcs;
extern int dynamicMinProcs;
extern int dynamicMaxClassProcs;
extern u_int dynamicKillInterval;
extern u_int dynamicUpdateInterval;
extern float dynamicGain;
extern int dynamicThreshold1;
extern int dynamicThresholdN;
extern u_int dynamicPleaseStartDelay;
extern u_int dynamicAppConnectTimeout;
extern char **dynamicEnvp;
extern u_int dynamicProcessSlack;
extern int dynamicAutoRestart;
extern int dynamicAutoUpdate;
extern u_int dynamicListenQueueDepth;
extern u_int dynamicInitStartDelay;
extern u_int dynamicRestartDelay;
extern array_header *dynamic_pass_headers;
extern u_int dynamic_idle_timeout;
extern int dynamicMinServerLife;
extern int dynamicFlush;

extern char *fcgienc_logpath;					/* FastCGIENC Log file path */
extern int fcgienc_loglevel;					/* FastCGIENC Log level */
extern apr_file_t *fcgienc_logfp;

extern char *fcgienc_memcached_server;
extern unsigned short fcgienc_memcached_port;

extern BOOL fcgienc_encrypt_flag;				/* encrypt flag */
extern BOOL fcgienc_decrypt_flag;				/* decrypt flag */

extern char *fcgienc_authserver;				/* FastCGIENC Auth Server */
extern char *fcgienc_masterkeyserver;			/* FastCGIENC Master Key Server */
extern char *fcgienc_datakeyserver;				/* FastCGIENC Data Key Server */

extern char *fcgienc_cryptkeystring;			/* FastCGIENC Key string if unavailable keyserver */

extern char *fcgienc_username;					/* FastCGIENC User Name */
extern char *fcgienc_password;					/* FastCGIENC Password */

extern module MODULE_VAR_EXPORT encrypt_module;

#endif  /* FCGIENC_H */

