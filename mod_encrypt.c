/*
 * mod_encrypt.c --
 *
 *  Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

/*
 * Module design notes.
 *
 * 1. Restart cleanup.
 *
 *   mod_encrypt spawns several processes: one process manager process
 *   and several application processes.  None of these processes
 *   handle SIGHUP, so they just go away when the Web server performs
 *   a restart (as Apache does every time it starts.)
 *
 *   In order to allow the process manager to properly cleanup the
 *   running encrypt processes (without being disturbed by Apache),
 *   an intermediate process was introduced.  The diagram is as follows;
 *
 *   ApacheWS --> MiddleProc --> ProcMgr --> FCGI processes
 *
 *   On a restart, ApacheWS sends a SIGKILL to MiddleProc and then
 *   collects it via waitpid().  The ProcMgr periodically checks for
 *   its parent (via getppid()) and if it does not have one, as in
 *   case when MiddleProc has terminated, ProcMgr issues a SIGTERM
 *   to all FCGI processes, waitpid()s on them and then exits, so it
 *   can be collected by init(1).  Doing it any other way (short of
 *   changing Apache API), results either in inconsistent results or
 *   in generation of zombie processes.
 *
 *   XXX: How does Apache 1.2 implement "gentle" restart
 *   that does not disrupt current connections?  How does
 *   gentle restart interact with restart cleanup?
 *
 * 2. Request timeouts.
 *
 *   Earlier versions of this module used ap_soft_timeout() rather than
 *   ap_hard_timeout() and ate FastCGIENC server output until it completed.
 *   This precluded the FastCGIENC server from having to implement a
 *   SIGPIPE handler, but meant hanging the application longer than
 *   necessary.  SIGPIPE handler now must be installed in ALL FastCGIENC
 *   applications.  The handler should abort further processing and go
 *   back into the accept() loop.
 *
 *   Although using ap_soft_timeout() is better than ap_hard_timeout()
 *   we have to be more careful about SIGINT handling and subsequent
 *   processing, so, for now, make it hard.
 */

#include <curl/curl.h>
#include "fcgienc.h"
#include "fcgienc_log.h"
#include "fcgienc_crypt.h"
#include "fcgienc_encap.h"
#include "fcgienc_memcache.h"

#ifdef APACHE2
#ifndef WIN32

#include <unistd.h>

#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "unixd.h"

#endif
#endif

#ifndef timersub
#define	timersub(a, b, result)                              \
do {                                                  \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
    if ((result)->tv_usec < 0) {                            \
        --(result)->tv_sec;                                 \
        (result)->tv_usec += 1000000;                       \
    }                                                       \
} while (0)
#endif

/*
 * Global variables
 */

pool *fcgienc_config_pool;            	 /* the config pool */
server_rec *fcgienc_apache_main_server;

const char *fcgienc_wrapper = NULL;          /* wrapper path */
uid_t fcgienc_user_id;                       /* the run uid of Apache & PM */
gid_t fcgienc_group_id;                      /* the run gid of Apache & PM */

fcgienc_server *fcgienc_servers = NULL;         /* AppClasses */

char *fcgienc_socket_dir = NULL;             /* default FastCgiEncIpcDir */

char *fcgienc_dynamic_dir = NULL;            /* directory for the dynamic
                                           * encrypt apps' sockets */

char *fcgienc_logpath = NULL;					/* FastCGIENC Log file path */
int fcgienc_loglevel = ENCRYPT_LOG_DEBUG;		/* FastCGIENC Log level */
apr_file_t *fcgienc_logfp = NULL;

char *fcgienc_memcached_server = "127.0.0.1";
unsigned short fcgienc_memcached_port = 11211;

BOOL fcgienc_encrypt_flag = TRUE;				/* encrypt flag */
BOOL fcgienc_decrypt_flag = TRUE;				/* decrypt flag */

char *fcgienc_authserver = NULL;				/* FastCGIENC Auth Server */
char *fcgienc_masterkeyserver = NULL;			/* FastCGIENC Master Key Server */
char *fcgienc_datakeyserver = NULL;				/* FastCGIENC Data Key Server */

char *fcgienc_cryptkeystring = NULL;			/* FastCGIENC Key string if unavailable keyserver */

char *fcgienc_username = NULL;					/* FastCGIENC User Name */
char *fcgienc_password = NULL;					/* FastCGIENC Password */

#ifdef WIN32

#pragma warning( disable : 4706 4100 4127)
fcgienc_pm_job *fcgienc_dynamic_mbox = NULL;
HANDLE *fcgienc_dynamic_mbox_mutex = NULL;
HANDLE fcgienc_pm_thread = INVALID_HANDLE_VALUE;

#else

int fcgienc_pm_pipe[2] = { -1, -1 };
pid_t fcgienc_pm_pid = -1;

#endif

char *fcgienc_empty_env = NULL;

u_int dynamicMaxProcs = FCGIENC_DEFAULT_MAX_PROCS;
int   dynamicMinProcs = FCGIENC_DEFAULT_MIN_PROCS;
int dynamicMaxClassProcs = FCGIENC_DEFAULT_MAX_CLASS_PROCS;
u_int dynamicKillInterval = FCGIENC_DEFAULT_KILL_INTERVAL;
u_int dynamicUpdateInterval = FCGIENC_DEFAULT_UPDATE_INTERVAL;
float dynamicGain = FCGIENC_DEFAULT_GAIN;
int dynamicThreshold1 = FCGIENC_DEFAULT_THRESHOLD_1;
int dynamicThresholdN = FCGIENC_DEFAULT_THRESHOLD_N;
u_int dynamicPleaseStartDelay = FCGIENC_DEFAULT_START_PROCESS_DELAY;
u_int dynamicAppConnectTimeout = FCGIENC_DEFAULT_APP_CONN_TIMEOUT;
char **dynamicEnvp = &fcgienc_empty_env;
u_int dynamicProcessSlack = FCGIENC_DEFAULT_PROCESS_SLACK;
int dynamicAutoRestart = FCGIENC_DEFAULT_RESTART_DYNAMIC;
int dynamicAutoUpdate = FCGIENC_DEFAULT_AUTOUPDATE;
int dynamicFlush = FCGIENC_FLUSH;
u_int dynamicListenQueueDepth = FCGIENC_DEFAULT_LISTEN_Q;
u_int dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
u_int dynamicRestartDelay = FCGIENC_DEFAULT_RESTART_DELAY;
array_header *dynamic_pass_headers = NULL;
u_int dynamic_idle_timeout = FCGIENC_DEFAULT_IDLE_TIMEOUT;
int dynamicMinServerLife = FCGIENC_DEFAULT_MIN_SERVER_LIFE;

/*******************************************************************************
 * Construct a message and write it to the pm_pipe.
 */
static void send_to_pm(const char id, const char * const fs_path,
     const char *user, const char * const group, const unsigned long q_usec,
     const unsigned long req_usec)
{
#ifdef WIN32
    fcgienc_pm_job *job = NULL;

    if (!(job = (fcgienc_pm_job *) malloc(sizeof(fcgienc_pm_job))))
       return;
#else
    static int failed_count = 0;
    int buflen = 0;
    char buf[FCGIENC_MAX_MSG_LEN];
#endif

    if (strlen(fs_path) > FCGIENC_MAXPATH) {
        ap_log_error(FCGIENC_LOG_ERR_NOERRNO, fcgienc_apache_main_server, 
            "FastCGIENC: the path \"%s\" is too long (>%d) for a dynamic server", fs_path, FCGIENC_MAXPATH);
        return;
    }

    switch(id) {

    case FCGIENC_SERVER_START_JOB:
    case FCGIENC_SERVER_RESTART_JOB:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->user = strdup(user);
        job->group = strdup(group);
        job->qsec = 0L;
        job->start_time = 0L;
#else
        buflen = sprintf(buf, "%c %s %s %s*", id, fs_path, user, group);
#endif
        break;

    case FCGIENC_REQUEST_TIMEOUT_JOB:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->user = strdup(user);
        job->group = strdup(group);
        job->qsec = 0L;
        job->start_time = 0L;
#else
        buflen = sprintf(buf, "%c %s %s %s*", id, fs_path, user, group);
#endif
        break;

    case FCGIENC_REQUEST_COMPLETE_JOB:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->qsec = q_usec;
        job->start_time = req_usec;
        job->user = strdup(user);
        job->group = strdup(group);
#else
        buflen = sprintf(buf, "%c %s %s %s %lu %lu*", id, fs_path, user, group, q_usec, req_usec);
#endif
        break;
    }

#ifdef WIN32
    if (fcgienc_pm_add_job(job)) return;

    SetEvent(fcgienc_event_handles[MBOX_EVENT]);
#else
    ASSERT(buflen <= FCGIENC_MAX_MSG_LEN);

    /* There is no apache flag or function that can be used to id
     * restart/shutdown pending so ignore the first few failures as
     * once it breaks it will stay broke */
    if (write(fcgienc_pm_pipe[1], (const void *)buf, buflen) != buflen 
        && failed_count++ > 10) 
    {
        ap_log_error(FCGIENC_LOG_WARN, fcgienc_apache_main_server,
            "FastCGIENC: write() to PM failed (ignore if a restart or shutdown is pending)");
    }
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * init_module
 *
 *      An Apache module initializer, called by the Apache core
 *      after reading the server config.
 *
 *      Start the process manager no matter what, since there may be a
 *      request for dynamic FastCGIENC applications without any being
 *      configured as static applications.  Also, check for the existence
 *      and create if necessary a subdirectory into which all dynamic
 *      sockets will go.
 *
 *----------------------------------------------------------------------
 */
#ifdef APACHE2
static apcb_t init_module(apr_pool_t * p, apr_pool_t * plog, 
                          apr_pool_t * tp, server_rec * s)
#else
static apcb_t init_module(server_rec *s, pool *p)
#endif
{
#ifndef WIN32
    const char *err;
#endif

    /* Register to reset to default values when the config pool is cleaned */
    ap_block_alarms();
    ap_register_cleanup(p, NULL, fcgienc_config_reset_globals, ap_null_cleanup);
    ap_unblock_alarms();

#ifdef APACHE2
    ap_add_version_component(p, "mod_encrypt/" MOD_ENCRYPT_VERSION);    
#else
    ap_add_version_component("mod_encrypt/" MOD_ENCRYPT_VERSION);
#endif

    fcgienc_config_set_fcgienc_uid_n_gid(1);

    /* keep these handy */
    fcgienc_config_pool = p;
    fcgienc_apache_main_server = s;

#ifdef WIN32
    if (fcgienc_socket_dir == NULL)
        fcgienc_socket_dir = DEFAULT_SOCK_DIR;
    fcgienc_dynamic_dir = ap_pstrcat(p, fcgienc_socket_dir, "dynamic", NULL);
#else

    if (fcgienc_socket_dir == NULL)
        fcgienc_socket_dir = ap_server_root_relative(p, DEFAULT_SOCK_DIR);

    /* Create Unix/Domain socket directory */
    if ((err = fcgienc_config_make_dir(p, fcgienc_socket_dir)))
        ap_log_error(FCGIENC_LOG_ERR, s, "FastCGIENC: %s", err);

    /* Create Dynamic directory */
    if ((err = fcgienc_config_make_dynamic_dir(p, 1)))
        ap_log_error(FCGIENC_LOG_ERR, s, "FastCGIENC: %s", err);

    /* Spawn the PM only once.  Under Unix, Apache calls init() routines
     * twice, once before detach() and once after.  Win32 doesn't detach.
     * Under DSO, DSO modules are unloaded between the two init() calls.
     * Under Unix, the -X switch causes two calls to init() but no detach
     * (but all subprocesses are wacked so the PM is toasted anyway)! */

#ifdef APACHE2
    {
        void * first_pass;
        apr_pool_userdata_get(&first_pass, "mod_encrypt", s->process->pool);
        if (first_pass == NULL) 
        {
            apr_pool_userdata_set((const void *)1, "mod_encrypt",
                                  apr_pool_cleanup_null, s->process->pool);
            return APCB_OK;
        }
    }
#else /* !APACHE2 */

    if (ap_standalone && ap_restart_time == 0)
        return;

#endif

    /* Create the pipe for comm with the PM */
    if (pipe(fcgienc_pm_pipe) < 0) {
        ap_log_error(FCGIENC_LOG_ERR, s, "FastCGIENC: pipe() failed");
    }

    /* Start the Process Manager */

#ifdef APACHE2
    {
        apr_proc_t * proc = apr_palloc(p, sizeof(*proc));
        apr_status_t rv;

        rv = apr_proc_fork(proc, tp);

        if (rv == APR_INCHILD)
        {
            /* child */
            fcgienc_pm_main(NULL);
            exit(1);
        }
        else if (rv != APR_INPARENT)
        {
            return rv;
        }

        /* parent */

        apr_pool_note_subprocess(p, proc, APR_KILL_ONLY_ONCE);
    }
#else /* !APACHE2 */

    fcgienc_pm_pid = ap_spawn_child(p, fcgienc_pm_main, NULL, kill_only_once, NULL, NULL, NULL);
    if (fcgienc_pm_pid <= 0) {
        ap_log_error(FCGIENC_LOG_ALERT, s,
            "FastCGIENC: can't start the process manager, spawn_child() failed");
    }

#endif /* !APACHE2 */

    close(fcgienc_pm_pipe[0]);

	/* Initialize Log path */
	{
		const char *err;

		/* Create log file */
		if (fcgienc_logpath)
		{
			if ((err = fcgienc_config_make_logfile(p, fcgienc_logpath)))
				log_message(ENCRYPT_LOG_ERR, "FastCGIENC: %s", err);
		}

		/* initialize global curl */
		curl_global_init(CURL_GLOBAL_DEFAULT);

		/* initialize memcached */
		if (memcache_init() != 0)
		{
			log_message(ENCRYPT_LOG_INFO, "%s", "Failed to initialize memcached, mod_encrypt will not accept the request");
		}
	}

	/* Initialize key process */
	{
		int ret;
		FILE *fp;
		char procpath[256];
		char command[1024];

		fp = popen("apxs -q exp_libexecdir", "r");
		if (fp != NULL)
		{
			if (fgets(procpath, 256, fp) == NULL)
			{
				log_message(ENCRYPT_LOG_INFO, "%s.", "Failed to start key process");
			}
			else
			{
				procpath[strlen(procpath)-1] = 0;
				sprintf(command, "%s/mod_enckeythread.bin %s %s %s %s %s %s-keys %s %d &", \
					procpath, fcgienc_authserver, fcgienc_masterkeyserver, fcgienc_datakeyserver, \
					fcgienc_username, fcgienc_password, fcgienc_logpath, \
					fcgienc_memcached_server, fcgienc_memcached_port);

				ret = system(command);
				log_message(ENCRYPT_LOG_INFO, "%s %d.", "Succeed to start key process", ret);
			}
						
			pclose(fp);
		}
		else
		{
			log_message(ENCRYPT_LOG_INFO, "%s.", "Failed to start key process");
		}
	}

	log_message(ENCRYPT_LOG_INFO, "%s", "Started mod_encrypt");

#endif /* !WIN32 */

    return APCB_OK;
}

#ifdef WIN32
#ifdef APACHE2
static apcb_t fcgienc_child_exit(void * dc)
#else
static apcb_t fcgienc_child_exit(server_rec *dc0, pool *dc1)
#endif 
{
    /* Signal the PM thread to exit*/
    SetEvent(fcgienc_event_handles[TERM_EVENT]);

    /* Waiting on pm thread to exit */
    WaitForSingleObject(fcgienc_pm_thread, INFINITE);

    return APCB_OK;
}
#endif /* WIN32 */

#ifdef APACHE2
static void fcgienc_child_init(apr_pool_t * p, server_rec * dc)
#else
static void fcgienc_child_init(server_rec *dc, pool *p)
#endif
{
#ifdef WIN32
    /* Create the MBOX, TERM, and WAKE event handlers */
    fcgienc_event_handles[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (fcgienc_event_handles[0] == NULL) {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server, 
            "FastCGIENC: CreateEvent() failed");
    }
    fcgienc_event_handles[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (fcgienc_event_handles[1] == NULL) {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server, 
            "FastCGIENC: CreateEvent() failed");
    }
    fcgienc_event_handles[2] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (fcgienc_event_handles[2] == NULL) {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server, 
            "FastCGIENC: CreateEvent() failed");
    }

    /* Create the mbox mutex (PM - request threads) */
    fcgienc_dynamic_mbox_mutex = CreateMutex(NULL, FALSE, NULL);
    if (fcgienc_dynamic_mbox_mutex == NULL) {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server, 
            "FastCGIENC: CreateMutex() failed");
    }

    /* Spawn of the process manager thread */
    fcgienc_pm_thread = (HANDLE) _beginthread(fcgienc_pm_main, 0, NULL);
    if (fcgienc_pm_thread == (HANDLE) -1) {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server, 
            "_beginthread() failed to spawn the process manager");
    }

	/* Initialize Log path */
	{
		const char *err;
		/* Create log file */
		if (fcgienc_logpath)
		{
			if ((err = fcgienc_config_make_logfile(p, fcgienc_logpath)))
				log_message(ENCRYPT_LOG_ERR, "FastCGIENC: %s", err);
		}

		/* initialize global curl */
		curl_global_init(CURL_GLOBAL_DEFAULT);

		/* initialize memcached */
		if (memcache_init() != 0)
		{
			log_message(ENCRYPT_LOG_INFO, "%s", "Failed to initialize memcached, mod_encrypt will not accept the request");
		}
	}

	log_message(ENCRYPT_LOG_INFO, "%s", "Started mod_encrypt");

#ifdef APACHE2
    apr_pool_cleanup_register(p, NULL, fcgienc_child_exit, fcgienc_child_exit);
#endif
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * get_header_line --
 *
 *      Terminate a line:  scan to the next newline, scan back to the
 *      first non-space character and store a terminating zero.  Return
 *      the next character past the end of the newline.
 *
 *      If the end of the string is reached, ASSERT!
 *
 *      If the FIRST character(s) in the line are '\n' or "\r\n", the
 *      first character is replaced with a NULL and next character
 *      past the newline is returned.  NOTE: this condition supercedes
 *      the processing of RFC-822 continuation lines.
 *
 *      If continuation is set to 'TRUE', then it parses a (possible)
 *      sequence of RFC-822 continuation lines.
 *
 * Results:
 *      As above.
 *
 * Side effects:
 *      Termination byte stored in string.
 *
 *----------------------------------------------------------------------
 */
static char *get_header_line(char *start, int continuation)
{
    char *p = start;
    char *end = start;

    if(p[0] == '\r'  &&  p[1] == '\n') { /* If EOL in 1st 2 chars */
        p++;                              /*   point to \n and stop */
    } else if(*p != '\n') {
        if(continuation) {
            while(*p != '\0') {
                if(*p == '\n' && p[1] != ' ' && p[1] != '\t')
                    break;
                p++;
            }
        } else {
            while(*p != '\0' && *p != '\n') {
                p++;
            }
        }
    }

    ASSERT(*p != '\0');
    end = p;
    end++;

    /*
     * Trim any trailing whitespace.
     */
    while(isspace((unsigned char)p[-1]) && p > start) {
        p--;
    }

    *p = '\0';
    return end;
}

#ifdef WIN32

static int set_nonblocking(const fcgienc_request * fr, int nonblocking)
{
    if (fr->using_npipe_io) 
    {
        if (nonblocking)
        {
            DWORD mode = PIPE_NOWAIT | PIPE_READMODE_BYTE;
            if (SetNamedPipeHandleState((HANDLE) fr->fd, &mode, NULL, NULL) == 0)
            {
		        ap_log_rerror(FCGIENC_LOG_ERR, fr->r,
                    "FastCGIENC: SetNamedPipeHandleState() failed");
                return -1;
            }
        }
    }
    else  
    {
        unsigned long ioctl_arg = (nonblocking) ? 1 : 0;
        if (ioctlsocket(fr->fd, FIONBIO, &ioctl_arg) != 0)
        {
            errno = WSAGetLastError();
            ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, fr->r, 
                "FastCGIENC: ioctlsocket() failed");
            return -1;
        }
    }

    return 0;
}

#else

static int set_nonblocking(const fcgienc_request * fr, int nonblocking)
{
    int nb_flag = 0;
    int fd_flags = fcntl(fr->fd, F_GETFL, 0);

    if (fd_flags < 0) return -1;

#if defined(O_NONBLOCK)
    nb_flag = O_NONBLOCK;
#elif defined(O_NDELAY)
    nb_flag = O_NDELAY;
#elif defined(FNDELAY)
    nb_flag = FNDELAY;
#else
#error "TODO - don't read from app until all data from client is posted."
#endif

    fd_flags = (nonblocking) ? (fd_flags | nb_flag) : (fd_flags & ~nb_flag);

    return fcntl(fr->fd, F_SETFL, fd_flags);
}

#endif

/*******************************************************************************
 * Close the connection to the FastCGIENC server.  This is normally called by
 * do_work(), but may also be called as in request pool cleanup.
 */
static void close_connection_to_fs(fcgienc_request *fr)
{
#ifdef WIN32

    if (fr->fd != INVALID_SOCKET)
    {
        set_nonblocking(fr, FALSE);

        if (fr->using_npipe_io)
        {
            CloseHandle((HANDLE) fr->fd);
        }
        else
        {
            /* abort the connection entirely */
            struct linger linger = {0, 0};
            setsockopt(fr->fd, SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof(linger)); 
            closesocket(fr->fd);
        }

        fr->fd = INVALID_SOCKET;

#else /* ! WIN32 */

    if (fr->fd >= 0) 
    {
        struct linger linger = {0, 0};
        set_nonblocking(fr, FALSE);
        /* abort the connection entirely */
        setsockopt(fr->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)); 
        close(fr->fd);
        fr->fd = -1;

#endif /* ! WIN32 */

        if (fr->dynamic && fr->keepReadingFromFcgiApp == FALSE) 
        {
            /* XXX FCGIENC_REQUEST_COMPLETE_JOB is only sent for requests which complete
             * normally WRT the fcgi app.  There is no data sent for
             * connect() timeouts or requests which complete abnormally.
             * KillDynamicProcs() and RemoveRecords() need to be looked at
             * to be sure they can reasonably handle these cases before
             * sending these sort of stats - theres some funk in there.
             */
            if (fcgienc_util_ticks(&fr->completeTime) < 0) 
            {
                /* there's no point to aborting the request, just log it */
                ap_log_error(FCGIENC_LOG_ERR, fr->r->server, "FastCGIENC: can't get time of day");
            }
        }
    }
}


/*
 *----------------------------------------------------------------------
 *
 * process_headers --
 *
 *      Call with r->parseHeader == SCAN_CGI_READING_HEADERS
 *      and initial script output in fr->header.
 *
 *      If the initial script output does not include the header
 *      terminator ("\r\n\r\n") process_headers returns with no side
 *      effects, to be called again when more script output
 *      has been appended to fr->header.
 *
 *      If the initial script output includes the header terminator,
 *      process_headers parses the headers and determines whether or
 *      not the remaining script output will be sent to the client.
 *      If so, process_headers sends the HTTP response headers to the
 *      client and copies any non-header script output to the output
 *      buffer reqOutbuf.
 *
 * Results:
 *      none.
 *
 * Side effects:
 *      May set r->parseHeader to:
 *        SCAN_CGI_FINISHED -- headers parsed, returning script response
 *        SCAN_CGI_BAD_HEADER -- malformed header from script
 *        SCAN_CGI_INT_REDIRECT -- handler should perform internal redirect
 *        SCAN_CGI_SRV_REDIRECT -- handler should return REDIRECT
 *
 *----------------------------------------------------------------------
 */

static const char *process_headers(request_rec *r, fcgienc_request *fr)
{
    char *p, *next, *name, *value;
    int len, flag;
    int hasContentType, hasStatus, hasLocation;

    ASSERT(fr->parseHeader == SCAN_CGI_READING_HEADERS);

    if (fr->header == NULL)
        return NULL;

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = (char *)fr->header->elts;
    len = fr->header->nelts;
    flag = 0;
    while(len-- && flag < 2) {
        switch(*p) {
            case '\r':
                break;
            case '\n':
                flag++;
                break;
            case '\0':
            case '\v':
            case '\f':
                name = "Invalid Character";
                goto BadHeader;
            default:
                flag = 0;
                break;
        }
        p++;
    }

    /* Return (to be called later when we have more data)
     * if we don't have an entire header. */
    if (flag < 2)
        return NULL;

    /*
     * Parse all the headers.
     */
    fr->parseHeader = SCAN_CGI_FINISHED;
    hasContentType = hasStatus = hasLocation = FALSE;
    next = (char *)fr->header->elts;
    for(;;) {
        next = get_header_line(name = next, TRUE);
        if (*name == '\0') {
            break;
        }
        if ((p = strchr(name, ':')) == NULL) {
            goto BadHeader;
        }
        value = p + 1;
        while (p != name && isspace((unsigned char)*(p - 1))) {
            p--;
        }
        if (p == name) {
            goto BadHeader;
        }
        *p = '\0';
        if (strpbrk(name, " \t") != NULL) {
            *p = ' ';
            goto BadHeader;
        }
        while (isspace((unsigned char)*value)) {
            value++;
        }

        if (strcasecmp(name, "Status") == 0) {
            int statusValue = strtol(value, NULL, 10);

            if (hasStatus) {
                goto DuplicateNotAllowed;
            }
            if (statusValue < 0) {
                fr->parseHeader = SCAN_CGI_BAD_HEADER;
                return ap_psprintf(r->pool, "invalid Status '%s'", value);
            }
            hasStatus = TRUE;
            r->status = statusValue;
            r->status_line = ap_pstrdup(r->pool, value);
            continue;
        }

        if (fr->role == FCGIENC_RESPONDER) {
            if (strcasecmp(name, "Content-type") == 0) {
                if (hasContentType) {
                    goto DuplicateNotAllowed;
                }
                hasContentType = TRUE;
#ifdef APACHE2                
                ap_set_content_type(r, value);
#else
                r->content_type = ap_pstrdup(r->pool, value);
#endif                
                continue;
            }

            if (strcasecmp(name, "Location") == 0) {
                if (hasLocation) {
                    goto DuplicateNotAllowed;
                }
                hasLocation = TRUE;
                ap_table_set(r->headers_out, "Location", value);
                continue;
            }

			if (strcasecmp(name, "Content-Range") == 0) {
				int startRange = 0, endRange = 0, sizeRange = 0;
				sscanf(value, "bytes %d-%d/%d", &startRange, &endRange, &sizeRange);
				fr->decryptor.offset = startRange;
			}

            /* If the script wants them merged, it can do it */
            ap_table_add(r->err_headers_out, name, value);
            continue;
        }
        else {
            ap_table_add(fr->authHeaders, name, value);
        }
    }

    if (fr->role != FCGIENC_RESPONDER)
        return NULL;

	/* decrypt parameters */

	{
		int ret;
		char *usermdStr;
		const char *usermdMetadata;
		int mkidLen, dkidLen, usermdLen;

		usermdMetadata = (const char *)ap_table_get(r->err_headers_out, "X-Scal-Usermd");

		if (usermdMetadata)
		{
			usermdLen = strlen(usermdMetadata);
			usermdStr = malloc(usermdLen+1);
			if (!usermdStr)
				return NULL;

			if (usermdLen > 2048)
				log_message(ENCRYPT_LOG_DEBUG, "received X-Scal-Usermd : too long to display");
			else
				log_message(ENCRYPT_LOG_DEBUG, "received X-Scal-Usermd : %s", usermdMetadata);

			mkidLen = 256; dkidLen = 256;
			ret = decap_metadata(usermdMetadata, strlen(usermdMetadata), \
				fr->decryptor.masterKeyId, &mkidLen, fr->decryptor.dataKeyId, &dkidLen, \
				usermdStr, &usermdLen);

			if (ret == 0) // if succeed
			{
				ap_table_unset(r->err_headers_out, "X-Scal-Usermd");

				if (usermdLen > 0)
				{
					ap_table_add(r->err_headers_out, "X-Scal-Usermd", usermdStr);
				}

				log_message(ENCRYPT_LOG_DEBUG, "masterKeyId : %s, dataKeyId : %s", fr->decryptor.masterKeyId, fr->decryptor.dataKeyId);

				if (fcgienc_decrypt_flag == TRUE)
				{
					ret = InitDecrypt(&fr->decryptor);
					if (ret != 0)
					{
						r->status = HTTP_SERVICE_UNAVAILABLE;
						r->header_only = TRUE;
						ap_table_unset(r->err_headers_out, "Content-Length");
					}
				}
			}

			free(usermdStr);
		}
	}

    /*
     * Who responds, this handler or Apache?
     */
    if (hasLocation) {
        const char *location = ap_table_get(r->headers_out, "Location");
        /*
         * Based on internal redirect handling in mod_cgi.c...
         *
         * If a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */
        if (r->status == 200) {
            if(location[0] == '/') {
                /*
                 * Location is an relative path.  This handler will
                 * consume all script output, then have Apache perform an
                 * internal redirect.
                 */
                fr->parseHeader = SCAN_CGI_INT_REDIRECT;
                return NULL;
            } else {
                /*
                 * Location is an absolute URL.  If the script didn't
                 * produce a Content-type header, this handler will
                 * consume all script output and then have Apache generate
                 * its standard redirect response.  Otherwise this handler
                 * will transmit the script's response.
                 */
                fr->parseHeader = SCAN_CGI_SRV_REDIRECT;
                return NULL;
            }
        }
    }
    /*
     * We're responding.  Send headers, buffer excess script output.
     */
    ap_send_http_header(r);

    /* We need to reinstate our timeout, send_http_header() kill()s it */
    ap_hard_timeout("FastCGIENC request processing", r);

    if (r->header_only) {
        /* we've got all we want from the server */
        close_connection_to_fs(fr);
        fr->exitStatusSet = 1;
        fcgienc_buf_reset(fr->clientOutputBuffer);
        fcgienc_buf_reset(fr->serverOutputBuffer);
        return NULL;
    }

    len = fr->header->nelts - (next - fr->header->elts);

    ASSERT(len >= 0);
    ASSERT(BufferLength(fr->clientOutputBuffer) == 0);
    
    if (BufferFree(fr->clientOutputBuffer) < len) {
        fr->clientOutputBuffer = fcgienc_buf_new(r->pool, len);
    }
    
    ASSERT(BufferFree(fr->clientOutputBuffer) >= len);

    if (len > 0) {
        int sent;
        sent = fcgienc_buf_add_block(fr->clientOutputBuffer, next, len);
        ASSERT(sent == len);
    }

    return NULL;

BadHeader:
    /* Log first line of a multi-line header */
    if ((p = strpbrk(name, "\r\n")) != NULL)
        *p = '\0';
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "malformed header '%s'", name);

DuplicateNotAllowed:
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "duplicate header '%s'", name);
}

/*
 * Read from the client filling both the FastCGIENC server buffer and the
 * client buffer with the hopes of buffering the client data before
 * making the connect() to the FastCGIENC server.  This prevents slow
 * clients from keeping the FastCGIENC server in processing longer than is
 * necessary.
 */
static int read_from_client_n_queue(fcgienc_request *fr)
{
    char *end;
    int count;
    long int countRead;

    while (BufferFree(fr->clientInputBuffer) > 0 || BufferFree(fr->serverOutputBuffer) > 0) {
        fcgienc_protocol_queue_client_buffer(fr);

        if (fr->expectingClientContent <= 0)
            return OK;

        fcgienc_buf_get_free_block_info(fr->clientInputBuffer, &end, &count);
        if (count == 0)
            return OK;

        if ((countRead = ap_get_client_block(fr->r, end, count)) < 0)
        {
            /* set the header scan state to done to prevent logging an error 
             * - hokey approach - probably should be using a unique value */
            fr->parseHeader = SCAN_CGI_FINISHED;
            return -1;
        }

        if (countRead == 0) {
            fr->expectingClientContent = 0;
        }
        else {
			if (fcgienc_encrypt_flag == TRUE)
				CryptDataStream(&fr->encryptor, end, 0, countRead);

			fcgienc_buf_add_update(fr->clientInputBuffer, countRead);
            ap_reset_timeout(fr->r);
        }
    }
    return OK;
}

static int write_to_client(fcgienc_request *fr)
{
    char *begin;
    int count;
    int rv;
#ifdef APACHE2
    apr_bucket * bkt;
    apr_bucket_brigade * bde;
    apr_bucket_alloc_t * const bkt_alloc = fr->r->connection->bucket_alloc;
#endif

    fcgienc_buf_get_block_info(fr->clientOutputBuffer, &begin, &count);
	if (fcgienc_decrypt_flag == TRUE)
	{
		CryptDataStream(&fr->decryptor, fr->clientOutputBuffer->data, fr->decryptor.offset, count);
		fr->decryptor.offset = 0;
	}
    if (count == 0)
        return OK;

    /* If fewer than count bytes are written, an error occured.
     * ap_bwrite() typically forces a flushed write to the client, this
     * effectively results in a block (and short packets) - it should
     * be fixed, but I didn't win much support for the idea on new-httpd.
     * So, without patching Apache, the best way to deal with this is
     * to size the fcgienc_bufs to hold all of the script output (within
     * reason) so the script can be released from having to wait around
     * for the transmission to the client to complete. */

#ifdef APACHE2

    bde = apr_brigade_create(fr->r->pool, bkt_alloc);
    bkt = apr_bucket_transient_create(begin, count, bkt_alloc);
    APR_BRIGADE_INSERT_TAIL(bde, bkt);

    if (fr->fs ? fr->fs->flush : dynamicFlush) 
    {
        bkt = apr_bucket_flush_create(bkt_alloc);
        APR_BRIGADE_INSERT_TAIL(bde, bkt);
    }

    rv = ap_pass_brigade(fr->r->output_filters, bde);

#elif defined(RUSSIAN_APACHE)

    rv = (ap_rwrite(begin, count, fr->r) != count);

#else

    rv = (ap_bwrite(fr->r->connection->client, begin, count) != count);

#endif

    if (rv || fr->r->connection->aborted) {
        ap_log_rerror(FCGIENC_LOG_INFO_NOERRNO, fr->r,
            "FastCGIENC: client stopped connection before send body completed");
        return -1;
    }

#ifndef APACHE2

    ap_reset_timeout(fr->r);

    /* Don't bother with a wrapped buffer, limiting exposure to slow
     * clients.  The BUFF routines don't allow a writev from above,
     * and don't always memcpy to minimize small write()s, this should
     * be fixed, but I didn't win much support for the idea on
     * new-httpd - I'll have to _prove_ its a problem first.. */

    /* The default behaviour used to be to flush with every write, but this
     * can tie up the FastCGIENC server longer than is necessary so its an option now */

    if (fr->fs ? fr->fs->flush : dynamicFlush) 
    {
#ifdef RUSSIAN_APACHE
        rv = ap_rflush(fr->r);
#else
        rv = ap_bflush(fr->r->connection->client);
#endif

        if (rv)
        {
            ap_log_rerror(FCGIENC_LOG_INFO_NOERRNO, fr->r,
                "FastCGIENC: client stopped connection before send body completed");
            return -1;
        }

        ap_reset_timeout(fr->r);
    }

#endif /* !APACHE2 */

    fcgienc_buf_toss(fr->clientOutputBuffer, count);
    return OK;
}

static void 
get_request_identity(request_rec * const r, 
                     uid_t * const uid, 
                     gid_t * const gid)
{
#if defined(WIN32) 
    *uid = (uid_t) 0;
    *gid = (gid_t) 0;
#elif defined(APACHE2)
    ap_unix_identity_t * identity = ap_run_get_suexec_identity(r);
    if (identity) 
    {
        *uid = identity->uid;
        *gid = identity->gid;
    }
    else
    {
        *uid = 0;
        *gid = 0;
    }
#else
    *uid = r->server->server_uid;
    *gid = r->server->server_gid;
#endif
}

/*******************************************************************************
 * Determine the user and group the wrapper should be called with.
 * Based on code in Apache's create_argv_cmd() (util_script.c).
 */
static void set_uid_n_gid(request_rec *r, const char **user, const char **group)
{
    if (fcgienc_wrapper == NULL) {
        *user = "-";
        *group = "-";
        return;
    }

    if (strncmp("/~", r->uri, 2) == 0) {
        /* its a user dir uri, just send the ~user, and leave it to the PM */
        char *end = strchr(r->uri + 2, '/');

        if (end)
            *user = memcpy(ap_pcalloc(r->pool, end - r->uri), r->uri + 1, end - r->uri - 1);
        else
            *user = ap_pstrdup(r->pool, r->uri + 1);
        *group = "-";
    }
    else {
        uid_t uid;
        gid_t gid;

        get_request_identity(r, &uid, &gid);

        *user = ap_psprintf(r->pool, "%ld", (long) uid);
        *group = ap_psprintf(r->pool, "%ld", (long) gid);
    }
}

static void send_request_complete(fcgienc_request *fr)
{
    if (fr->completeTime.tv_sec) 
    {
        struct timeval qtime, rtime;

        timersub(&fr->queueTime, &fr->startTime, &qtime);
        timersub(&fr->completeTime, &fr->queueTime, &rtime);
        
        send_to_pm(FCGIENC_REQUEST_COMPLETE_JOB, fr->fs_path,
            fr->user, fr->group,
            qtime.tv_sec * 1000000 + qtime.tv_usec,
            rtime.tv_sec * 1000000 + rtime.tv_usec);
    }
}


/*******************************************************************************
 * Connect to the FastCGIENC server.
 */
static int open_connection_to_fs(fcgienc_request *fr)
{
    struct timeval  tval;
    fd_set          write_fds, read_fds;
    int             status;
    request_rec * const r = fr->r;
    pool * const rp = r->pool;
    const char *socket_path = NULL;
    struct sockaddr *socket_addr = NULL;
    int socket_addr_len = 0;
#ifndef WIN32
    const char *err = NULL;
#endif

    /* Create the connection point */
    if (fr->dynamic) 
    {
        socket_path = fcgienc_util_socket_hash_filename(rp, fr->fs_path, fr->user, fr->group);
        socket_path = fcgienc_util_socket_make_path_absolute(rp, socket_path, 1);

#ifndef WIN32
        err = fcgienc_util_socket_make_domain_addr(rp, (struct sockaddr_un **)&socket_addr,
                                      &socket_addr_len, socket_path);
        if (err) {
            ap_log_rerror(FCGIENC_LOG_ERR, r,
                "FastCGIENC: failed to connect to (dynamic) server \"%s\": "
                "%s", fr->fs_path, err);
            return FCGIENC_FAILED;
        }
#endif
    } 
    else 
    {
#ifdef WIN32
        if (fr->fs->dest_addr != NULL) {
            socket_addr = fr->fs->dest_addr;
        }
        else if (fr->fs->socket_addr) {
            socket_addr = fr->fs->socket_addr;
        }
        else {
            socket_path = fr->fs->socket_path;
        }
#else
        socket_addr = fr->fs->socket_addr;
#endif
        socket_addr_len = fr->fs->socket_addr_len;
    }

    if (fr->dynamic)
    {
#ifdef WIN32
        if (fr->fs && fr->fs->restartTime)
#else
        struct stat sock_stat;
        
        if (stat(socket_path, &sock_stat) == 0)
#endif
        {
            /* It exists */
            if (dynamicAutoUpdate) 
            {
                struct stat app_stat;
        
                /* TODO: follow sym links */
        
                if (stat(fr->fs_path, &app_stat) == 0)
                {
#ifdef WIN32
                    if (fr->fs->startTime < app_stat.st_mtime)
#else
                    if (sock_stat.st_mtime < app_stat.st_mtime)
#endif
                    {
#ifndef WIN32
                        struct timeval tv;
                        
                        tv.tv_sec = 1;
                        tv.tv_usec = 0;
#endif
                        /* 
                         * There's a newer one, request a restart.
                         */
                        send_to_pm(FCGIENC_SERVER_RESTART_JOB, fr->fs_path, fr->user, fr->group, 0, 0);

#ifdef WIN32
                        Sleep(1000);
#else
                        /* Avoid sleep/alarm interactions */
                        ap_select(0, NULL, NULL, NULL, &tv);
#endif
                    }
                }
            }
        }
        else
        {
            int i;

            send_to_pm(FCGIENC_SERVER_START_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
        
            /* wait until it looks like its running - this shouldn't take
             * very long at all - the exception is when the sockets are 
             * removed out from under a running application - the loop 
             * limit addresses this (preventing spinning) */

            for (i = 10; i > 0; i--)
            {
#ifdef WIN32
                Sleep(500);

                fr->fs = fcgienc_util_fs_get_by_id(fr->fs_path, 0, 0);

                if (fr->fs && fr->fs->restartTime)
#else
            	struct timeval tv;
                
                tv.tv_sec = 0;
              	tv.tv_usec =  500000;
                
                /* Avoid sleep/alarm interactions */
                ap_select(0, NULL, NULL, NULL, &tv);

                if (stat(socket_path, &sock_stat) == 0)
#endif
                {
                    break;
                }
            }

            if (i <= 0)
            {
                ap_log_rerror(FCGIENC_LOG_ALERT, r,
                    "FastCGIENC: failed to connect to (dynamic) server \"%s\": "
                    "something is seriously wrong, any chance the "
                    "socket/named_pipe directory was removed?, see the "
                    "FastCgiEncIpcDir directive", fr->fs_path);
                return FCGIENC_FAILED;
            }
        }
    }

#ifdef WIN32
    if (socket_path) 
    {
        BOOL ready;
        DWORD connect_time;
        int rv;
        HANDLE wait_npipe_mutex;
        DWORD interval;
        DWORD max_connect_time = FCGIENC_NAMED_PIPE_CONNECT_TIMEOUT;
            
        fr->using_npipe_io = TRUE;

        if (fr->dynamic) 
        {
            interval = dynamicPleaseStartDelay * 1000;
            
            if (dynamicAppConnectTimeout) {
                max_connect_time = dynamicAppConnectTimeout;
            }
        }
        else
        {
            interval = FCGIENC_NAMED_PIPE_CONNECT_TIMEOUT * 1000;
            
            if (fr->fs->appConnectTimeout) {
                max_connect_time = fr->fs->appConnectTimeout;
            }
        }

        fcgienc_util_ticks(&fr->startTime);

        {
            /* xxx this handle should live somewhere (see CloseHandle()s below too) */
            char * wait_npipe_mutex_name, * cp;
            wait_npipe_mutex_name = cp = ap_pstrdup(rp, socket_path);
            while ((cp = strchr(cp, '\\'))) *cp = '/';
            
            wait_npipe_mutex = CreateMutex(NULL, FALSE, wait_npipe_mutex_name);
        }
        
        if (wait_npipe_mutex == NULL)
        {
            ap_log_rerror(FCGIENC_LOG_ERR, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "can't create the WaitNamedPipe mutex", fr->fs_path);
            return FCGIENC_FAILED;
        }
        
        SetLastError(ERROR_SUCCESS);
        
        rv = WaitForSingleObject(wait_npipe_mutex, max_connect_time * 1000);
        
        if (rv == WAIT_TIMEOUT || rv == WAIT_FAILED)
        {
            if (fr->dynamic) 
            {
                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
            }
            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "wait for a npipe instance failed", fr->fs_path);
            FCGIDBG3("interval=%d, max_connect_time=%d", interval, max_connect_time);
            CloseHandle(wait_npipe_mutex);
            return FCGIENC_FAILED; 
        }
        
        fcgienc_util_ticks(&fr->queueTime);
        
        connect_time = fr->queueTime.tv_sec - fr->startTime.tv_sec;
        
        if (fr->dynamic)
        {
            if (connect_time >= interval)
            {
                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
                FCGIDBG4("connect_time=%d, interval=%d, max_connect_time=%d", connect_time, interval, max_connect_time);
            }
            if (max_connect_time - connect_time < interval)
            {
                interval = max_connect_time - connect_time;
            }
        }
        else
        {
            interval -= connect_time * 1000;
        }

        for (;;)
        {
            ready = WaitNamedPipe(socket_path, interval);

            if (ready)
            {
                fr->fd = (SOCKET) CreateFile(socket_path, 
                    GENERIC_READ | GENERIC_WRITE, 
                    FILE_SHARE_READ | FILE_SHARE_WRITE, 
                    NULL,                  /* no security attributes */
                    OPEN_EXISTING,         /* opens existing pipe */
                    FILE_FLAG_OVERLAPPED, 
                    NULL);                 /* no template file */

                if (fr->fd != (SOCKET) INVALID_HANDLE_VALUE) 
                {
                    ReleaseMutex(wait_npipe_mutex);
                    CloseHandle(wait_npipe_mutex);
                    fcgienc_util_ticks(&fr->queueTime);
                    FCGIDBG2("got npipe connect: %s", fr->fs_path);
                    return FCGIENC_OK;
                }

                if (GetLastError() != ERROR_PIPE_BUSY 
                    && GetLastError() != ERROR_FILE_NOT_FOUND) 
                {
                    ap_log_rerror(FCGIENC_LOG_ERR, r,
                        "FastCGIENC: failed to connect to server \"%s\": "
                        "CreateFile() failed", fr->fs_path);
                    break; 
                }

                FCGIDBG2("missed npipe connect: %s", fr->fs_path);
            }
        
            if (fr->dynamic) 
            {
                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
            }

            fcgienc_util_ticks(&fr->queueTime);

            connect_time = fr->queueTime.tv_sec - fr->startTime.tv_sec;

            FCGIDBG5("interval=%d, max_connect_time=%d, connect_time=%d, ready=%d", interval, max_connect_time, connect_time, ready);

            if (connect_time >= max_connect_time)
            {
                ap_log_rerror(FCGIENC_LOG_ERR, r,
                    "FastCGIENC: failed to connect to server \"%s\": "
                    "CreateFile()/WaitNamedPipe() timed out", fr->fs_path);
                break;
            }
        }

        ReleaseMutex(wait_npipe_mutex);
        CloseHandle(wait_npipe_mutex);
        fr->fd = INVALID_SOCKET;
        return FCGIENC_FAILED; 
    }
            
#endif

    /* Create the socket */
    fr->fd = socket(socket_addr->sa_family, SOCK_STREAM, 0);

#ifdef WIN32
    if (fr->fd == INVALID_SOCKET) {
        errno = WSAGetLastError();  /* Not sure this is going to work as expected */
#else    
    if (fr->fd < 0) {
#endif
        ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "socket() failed", fr->fs_path);
        return FCGIENC_FAILED; 
    }

#ifndef WIN32
    if (fr->fd >= FD_SETSIZE) {
        ap_log_rerror(FCGIENC_LOG_ERR, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "socket file descriptor (%u) is larger than "
            "FD_SETSIZE (%u), you probably need to rebuild Apache with a "
            "larger FD_SETSIZE", fr->fs_path, fr->fd, FD_SETSIZE);
        return FCGIENC_FAILED;
    }
#endif

    /* If appConnectTimeout is non-zero, setup do a non-blocking connect */
    if ((fr->dynamic && dynamicAppConnectTimeout) || (!fr->dynamic && fr->fs->appConnectTimeout)) {
        set_nonblocking(fr, TRUE);
    }

    if (fr->dynamic) {
        fcgienc_util_ticks(&fr->startTime);
    }

    /* Connect */
    if (connect(fr->fd, (struct sockaddr *)socket_addr, socket_addr_len) == 0)
        goto ConnectionComplete;

#ifdef WIN32

    errno = WSAGetLastError();
    if (errno != WSAEWOULDBLOCK) {
        ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "connect() failed", fr->fs_path);
        return FCGIENC_FAILED;
    }

#else

    /* ECONNREFUSED means the listen queue is full (or there isn't one).
     * With dynamic I can at least make sure the PM knows this is occuring */
    if (fr->dynamic && errno == ECONNREFUSED) {
        /* @@@ This might be better as some other "kind" of message */
        send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);

        errno = ECONNREFUSED;
    }

    if (errno != EINPROGRESS) {
        ap_log_rerror(FCGIENC_LOG_ERR, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "connect() failed", fr->fs_path);
        return FCGIENC_FAILED;
    }

#endif

    /* The connect() is non-blocking */

    errno = 0;

    if (fr->dynamic) {
        do {
            FD_ZERO(&write_fds);
            FD_SET(fr->fd, &write_fds);
            read_fds = write_fds;
            tval.tv_sec = dynamicPleaseStartDelay;
            tval.tv_usec = 0;

            status = ap_select((fr->fd+1), &read_fds, &write_fds, NULL, &tval);
            if (status < 0)
                break;

            fcgienc_util_ticks(&fr->queueTime);

            if (status > 0)
                break;

            /* select() timed out */
            send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
        } while ((fr->queueTime.tv_sec - fr->startTime.tv_sec) < (int)dynamicAppConnectTimeout);

        /* XXX These can be moved down when dynamic vars live is a struct */
        if (status == 0) {
            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "connect() timed out (appConnTimeout=%dsec)", 
                fr->fs_path, dynamicAppConnectTimeout);
            return FCGIENC_FAILED;
        }
    }  /* dynamic */
    else {
        tval.tv_sec = fr->fs->appConnectTimeout;
        tval.tv_usec = 0;
        FD_ZERO(&write_fds);
        FD_SET(fr->fd, &write_fds);
        read_fds = write_fds;

        status = ap_select((fr->fd+1), &read_fds, &write_fds, NULL, &tval);

        if (status == 0) {
            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "connect() timed out (appConnTimeout=%dsec)", 
                fr->fs_path, dynamicAppConnectTimeout);
            return FCGIENC_FAILED;
        }
    }  /* !dynamic */

    if (status < 0) {
#ifdef WIN32
        errno = WSAGetLastError(); 
#endif
        ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "select() failed", fr->fs_path);
        return FCGIENC_FAILED;
    }

    if (FD_ISSET(fr->fd, &write_fds) || FD_ISSET(fr->fd, &read_fds)) {
        int error = 0;
        NET_SIZE_T len = sizeof(error);

        if (getsockopt(fr->fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
            /* Solaris pending error */
#ifdef WIN32
            errno = WSAGetLastError(); 
#endif
            ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "select() failed (Solaris pending error)", fr->fs_path);
            return FCGIENC_FAILED;
        }

        if (error != 0) {
            /* Berkeley-derived pending error */
            errno = error;
            ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
                "FastCGIENC: failed to connect to server \"%s\": "
                "select() failed (pending error)", fr->fs_path);
            return FCGIENC_FAILED;
        }
    } 
    else {
#ifdef WIN32
        errno = WSAGetLastError();
#endif
        ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r,
            "FastCGIENC: failed to connect to server \"%s\": "
            "select() error - THIS CAN'T HAPPEN!", fr->fs_path);
        return FCGIENC_FAILED;
    }

ConnectionComplete:
    /* Return to blocking mode if it was set up */
    if ((fr->dynamic && dynamicAppConnectTimeout) || (!fr->dynamic && fr->fs->appConnectTimeout)) {
        set_nonblocking(fr, FALSE);
    }

#ifdef TCP_NODELAY
    if (socket_addr->sa_family == AF_INET) {
        /* We shouldn't be sending small packets and there's no application
         * level ack of the data we send, so disable Nagle */
        int set = 1;
        setsockopt(fr->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
    }
#endif

    return FCGIENC_OK;
}

static void sink_client_data(fcgienc_request *fr)
{
    char *base;
    int size;

    fcgienc_buf_reset(fr->clientInputBuffer);
    fcgienc_buf_get_free_block_info(fr->clientInputBuffer, &base, &size);
	while (ap_get_client_block(fr->r, base, size) > 0);
}

static apcb_t cleanup(void *data)
{
    fcgienc_request * const fr = (fcgienc_request *) data;

    if (fr == NULL) return APCB_OK;

    /* its more than likely already run, but... */
    close_connection_to_fs(fr);

    send_request_complete(fr);

    if (fr->fs_stderr_len) {
        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
            "FastCGIENC: server \"%s\" stderr: %s", fr->fs_path, fr->fs_stderr);
    }

    return APCB_OK;
}

#ifdef WIN32
static int npipe_io(fcgienc_request * const fr)
{
    request_rec * const r = fr->r;
    enum 
    {
        STATE_ENV_SEND,
        STATE_CLIENT_RECV,
        STATE_SERVER_SEND,
        STATE_SERVER_RECV,
        STATE_CLIENT_SEND,
        STATE_ERROR
    }
    state = STATE_ENV_SEND;
    env_status env_status;
    int client_recv;
    int dynamic_first_recv = fr->dynamic;
    int idle_timeout = fr->dynamic ? dynamic_idle_timeout : fr->fs->idle_timeout;
    int send_pending = 0;
    int recv_pending = 0;
    int client_send = 0;
    int rv;
    OVERLAPPED rov = { 0 }; 
    OVERLAPPED sov = { 0 };
    HANDLE events[2];
    struct timeval timeout;
    struct timeval dynamic_last_io_time;
    int did_io = 1;
    pool * const rp = r->pool;
    int is_connected = 0;
    DWORD recv_count = 0;

    dynamic_last_io_time.tv_sec = 0;
    dynamic_last_io_time.tv_usec = 0;
    
    if (fr->role == FCGIENC_RESPONDER)
    {
        client_recv = (fr->expectingClientContent != 0);
    }

    idle_timeout = fr->dynamic ? dynamic_idle_timeout : fr->fs->idle_timeout;

    env_status.envp = NULL;

    events[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
    events[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
    sov.hEvent = events[0];
    rov.hEvent = events[1];

    if (fr->dynamic) 
    {
        dynamic_last_io_time = fr->startTime;

        if (dynamicAppConnectTimeout) 
        {
            struct timeval qwait;
            timersub(&fr->queueTime, &fr->startTime, &qwait);
            dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
        }
    }

    ap_hard_timeout("FastCGIENC request processing", r);

    while (state != STATE_CLIENT_SEND)
    {
        DWORD msec_timeout;

        switch (state)
        {
        case STATE_ENV_SEND:

            if (fcgienc_protocol_queue_env(r, fr, &env_status) == 0)
            {
                goto SERVER_SEND;
            }
            
            state = STATE_CLIENT_RECV;

            /* fall through */
            
        case STATE_CLIENT_RECV:

            if (read_from_client_n_queue(fr) != OK)
            {
                state = STATE_ERROR;
                break;
            }

            if (fr->eofSent)
            {
                state = STATE_SERVER_SEND;
            }

            /* fall through */

SERVER_SEND:

        case STATE_SERVER_SEND:

            if (! is_connected) 
            {
                if (open_connection_to_fs(fr) != FCGIENC_OK) 
                {
                    ap_kill_timeout(r);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                is_connected = 1;
            }

            if (! send_pending && BufferLength(fr->serverOutputBuffer))
            {
                Buffer * b = fr->serverOutputBuffer;
                DWORD sent, len;
                
                len = min(b->length, b->data + b->size - b->begin);

                if (WriteFile((HANDLE) fr->fd, b->begin, len, &sent, &sov))
                {
                    /* sov.hEvent is set */
                    fcgienc_buf_removed(b, sent);
                }
                else if (GetLastError() == ERROR_IO_PENDING)
                {
                    send_pending = 1;
                }
                else
                {
                    ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                        "\"%s\" aborted: WriteFile() failed", fr->fs_path);
                    state = STATE_ERROR;
                    break;
                }
            }

            /* fall through */

        case STATE_SERVER_RECV:

            /* 
             * Only get more data when the serverInputBuffer is empty.
             * Otherwise we may already have the END_REQUEST buffered 
             * (but not processed) and a read on a closed named pipe 
             * results in an error that is normally abnormal.
             */
            if (! recv_pending && BufferLength(fr->serverInputBuffer) == 0)
            {
                Buffer * b = fr->serverInputBuffer;
                DWORD rcvd, len;
                
                len = min(b->size - b->length, b->data + b->size - b->end);

                if (ReadFile((HANDLE) fr->fd, b->end, len, &rcvd, &rov))
                {
                    fcgienc_buf_added(b, rcvd);
                    recv_count += rcvd;
                    ResetEvent(rov.hEvent);
                    if (dynamic_first_recv)
                    {
                        dynamic_first_recv = 0;
                    }
                }
                else if (GetLastError() == ERROR_IO_PENDING)
                {
                    recv_pending = 1;
                }
                else if (GetLastError() == ERROR_HANDLE_EOF)
                {
                    fr->keepReadingFromFcgiApp = FALSE;
                    state = STATE_CLIENT_SEND;
                    ResetEvent(rov.hEvent);
                    break;
                }
                else if (GetLastError() == ERROR_NO_DATA)
                {
                    break;
                }
                else
                {
                    ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                        "\"%s\" aborted: ReadFile() failed", fr->fs_path);
                    state = STATE_ERROR;
                    break;
                }
            }

            /* fall through */

        case STATE_CLIENT_SEND:

            if (client_send || ! BufferFree(fr->clientOutputBuffer))
            {
                if (write_to_client(fr)) 
                {
                    state = STATE_ERROR;
                    break;
                }

                client_send = 0;
            }

            break;

        default:

            ASSERT(0);
        }

        if (state == STATE_ERROR)
        {
            break;
        }

        /* setup the io timeout */

        if (BufferLength(fr->clientOutputBuffer))
        {
            /* don't let client data sit too long, it might be a push */
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
        }
        else if (dynamic_first_recv)
        {
            int delay;
            struct timeval qwait;

            fcgienc_util_ticks(&fr->queueTime);

            if (did_io) 
            {
                /* a send() succeeded last pass */
                dynamic_last_io_time = fr->queueTime;
            }
            else 
            {
                /* timed out last pass */
                struct timeval idle_time;
        
                timersub(&fr->queueTime, &dynamic_last_io_time, &idle_time);
        
                if (idle_time.tv_sec > idle_timeout) 
                {
                    send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
                    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: comm "
                        "with (dynamic) server \"%s\" aborted: (first read) "
                        "idle timeout (%d sec)", fr->fs_path, idle_timeout);
                    state = STATE_ERROR;
                    break;
                }
            }

            timersub(&fr->queueTime, &fr->startTime, &qwait);

            delay = dynamic_first_recv * dynamicPleaseStartDelay;

            if (qwait.tv_sec < delay) 
            {
                timeout.tv_sec = delay;
                timeout.tv_usec = 100000;  /* fudge for select() slop */
                timersub(&timeout, &qwait, &timeout);
            }
            else 
            {
                /* Killed time somewhere.. client read? */
                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
                dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                timeout.tv_sec = dynamic_first_recv * dynamicPleaseStartDelay;
                timeout.tv_usec = 100000;  /* fudge for select() slop */
                timersub(&timeout, &qwait, &timeout);
            }
        }
        else
        {
            timeout.tv_sec = idle_timeout;
            timeout.tv_usec = 0;
        }

        /* require a pended recv otherwise the app can deadlock */
        if (recv_pending)
        {
            msec_timeout = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;

            rv = WaitForMultipleObjects(2, events, FALSE, msec_timeout);

            if (rv == WAIT_TIMEOUT)
            {
                did_io = 0;

                if (BufferLength(fr->clientOutputBuffer))
                {
                    client_send = 1;
                }
                else if (dynamic_first_recv)
                {
                    struct timeval qwait;

                    fcgienc_util_ticks(&fr->queueTime);
                    timersub(&fr->queueTime, &fr->startTime, &qwait);

                    send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);

                    dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                }
                else
                {
                    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: comm with "
                        "server \"%s\" aborted: idle timeout (%d sec)",
                        fr->fs_path, idle_timeout);
                    state = STATE_ERROR;
                    break;
                }
            }
            else
            {
                int i = rv - WAIT_OBJECT_0;
            
                did_io = 1;

                if (i == 0)
                {
                    if (send_pending)
                    {
                        DWORD sent;

                        if (GetOverlappedResult((HANDLE) fr->fd, &sov, &sent, FALSE))
                        {
                            send_pending = 0;
                            fcgienc_buf_removed(fr->serverOutputBuffer, sent);
                        }
                        else
                        {
                            ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                                "\"%s\" aborted: GetOverlappedResult() failed", fr->fs_path);
                            state = STATE_ERROR;
                            break;
                        }
                    }

                    ResetEvent(sov.hEvent);
                }
                else
                {
                    DWORD rcvd;

                    ASSERT(i == 1);

                    recv_pending = 0;
                    ResetEvent(rov.hEvent);

                    if (GetOverlappedResult((HANDLE) fr->fd, &rov, &rcvd, FALSE))
                    {
                        fcgienc_buf_added(fr->serverInputBuffer, rcvd);
                        if (dynamic_first_recv)
                        {
                            dynamic_first_recv = 0;
                        }
                    }
                    else
                    {
                        ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                            "\"%s\" aborted: GetOverlappedResult() failed", fr->fs_path);
                        state = STATE_ERROR;
                        break;
                    }
                }
            }
        }

        if (fcgienc_protocol_dequeue(rp, fr)) 
        {
            state = STATE_ERROR;
            break;
        }
        
        if (fr->parseHeader == SCAN_CGI_READING_HEADERS) 
        {
            const char * err = process_headers(r, fr);
            if (err)
            {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                    "FastCGIENC: comm with server \"%s\" aborted: "
                    "error parsing headers: %s", fr->fs_path, err);
                state = STATE_ERROR;
                break;
            }
        }

        if (fr->exitStatusSet) 
        {
            fr->keepReadingFromFcgiApp = FALSE;
            state = STATE_CLIENT_SEND;
            break;
        }
    }

    if (! fr->exitStatusSet || ! fr->eofSent) 
    {
        CancelIo((HANDLE) fr->fd);
    }

    CloseHandle(rov.hEvent);
    CloseHandle(sov.hEvent);

    return (state == STATE_ERROR);
}
#endif /* WIN32 */

static int socket_io(fcgienc_request * const fr)
{
    enum 
    {
        STATE_SOCKET_NONE,
        STATE_ENV_SEND,
        STATE_CLIENT_RECV,
        STATE_SERVER_SEND,
        STATE_SERVER_RECV,
        STATE_CLIENT_SEND,
        STATE_ERROR,
        STATE_CLIENT_ERROR
    }
    state = STATE_ENV_SEND;

    request_rec * const r = fr->r;

    struct timeval timeout;
    struct timeval dynamic_last_io_time;
    fd_set read_set;
    fd_set write_set;
    int nfds = 0;
    int select_status = 1;
    int idle_timeout;
    int rv;
    int dynamic_first_recv = fr->dynamic ? 1 : 0;
    int client_send = FALSE;
    int client_recv = FALSE;
    env_status env;
    pool *rp = r->pool;
    int is_connected = 0;
    
    dynamic_last_io_time.tv_sec = 0;
    dynamic_last_io_time.tv_usec = 0;
    
    if (fr->role == FCGIENC_RESPONDER) 
    {
        client_recv = (fr->expectingClientContent != 0);
    }

    idle_timeout = fr->dynamic ? dynamic_idle_timeout : fr->fs->idle_timeout;

    env.envp = NULL;

    if (fr->dynamic) 
    {
        dynamic_last_io_time = fr->startTime;

        if (dynamicAppConnectTimeout) 
        {
            struct timeval qwait;
            timersub(&fr->queueTime, &fr->startTime, &qwait);
            dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
        }
    }

    ap_hard_timeout("FastCGIENC request processing", r);

    for (;;)
    {
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        switch (state)
        {
        case STATE_ENV_SEND:

            if (fcgienc_protocol_queue_env(r, fr, &env) == 0)
            {
                goto SERVER_SEND;
            }

            state = STATE_CLIENT_RECV;

            /* fall through */

        case STATE_CLIENT_RECV:

            if (read_from_client_n_queue(fr))
            {
                state = STATE_CLIENT_ERROR;
                break;
            }

            if (fr->eofSent)
            {
                state = STATE_SERVER_SEND;
            }

            /* fall through */

SERVER_SEND:

        case STATE_SERVER_SEND:

            if (! is_connected) 
            {
                if (open_connection_to_fs(fr) != FCGIENC_OK) 
                {
                    ap_kill_timeout(r);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                set_nonblocking(fr, TRUE);
                is_connected = 1;
                nfds = fr->fd + 1;
            }

            if (BufferLength(fr->serverOutputBuffer))
            {
                FD_SET(fr->fd, &write_set);
            }
            else
            {
                ASSERT(fr->eofSent);
                state = STATE_SERVER_RECV;
            }

            /* fall through */

        case STATE_SERVER_RECV:

            FD_SET(fr->fd, &read_set);

            /* fall through */

        case STATE_CLIENT_SEND:

            if (client_send || ! BufferFree(fr->clientOutputBuffer)) 
            {
                if (write_to_client(fr)) 
                {
                    state = STATE_CLIENT_ERROR;
                    break;
                }

                client_send = 0;
            }

            break;

        case STATE_ERROR:
        case STATE_CLIENT_ERROR:

            break;

        default:

            ASSERT(0);
        }

        if (state == STATE_CLIENT_ERROR || state == STATE_ERROR)
        {
            break;
        }

        /* setup the io timeout */

        if (BufferLength(fr->clientOutputBuffer))
        {
            /* don't let client data sit too long, it might be a push */
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
        }
        else if (dynamic_first_recv)
        {
            int delay;
            struct timeval qwait;

            fcgienc_util_ticks(&fr->queueTime);

            if (select_status) 
            {
                /* a send() succeeded last pass */
                dynamic_last_io_time = fr->queueTime;
            }
            else 
            {
                /* timed out last pass */
                struct timeval idle_time;
        
                timersub(&fr->queueTime, &dynamic_last_io_time, &idle_time);
        
                if (idle_time.tv_sec > idle_timeout) 
                {
                    send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
                    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: comm "
                        "with (dynamic) server \"%s\" aborted: (first read) "
                        "idle timeout (%d sec)", fr->fs_path, idle_timeout);
                    state = STATE_ERROR;
                    break;
                }
            }

            timersub(&fr->queueTime, &fr->startTime, &qwait);

            delay = dynamic_first_recv * dynamicPleaseStartDelay;

	    FCGIDBG5("qwait=%ld.%06ld delay=%d first_recv=%d", qwait.tv_sec, qwait.tv_usec, delay, dynamic_first_recv);

            if (qwait.tv_sec < delay) 
            {
                timeout.tv_sec = delay;
                timeout.tv_usec = 100000;  /* fudge for select() slop */
                timersub(&timeout, &qwait, &timeout);
            }
            else 
            {
                /* Killed time somewhere.. client read? */
                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);
                dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                timeout.tv_sec = dynamic_first_recv * dynamicPleaseStartDelay;
                timeout.tv_usec = 100000;  /* fudge for select() slop */
                timersub(&timeout, &qwait, &timeout);
            }
        }
        else
        {
            timeout.tv_sec = idle_timeout;
            timeout.tv_usec = 0;
        }

        /* wait on the socket */
        select_status = ap_select(nfds, &read_set, &write_set, NULL, &timeout);

        if (select_status < 0)
        {
            ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r, "FastCGIENC: comm with server "
                "\"%s\" aborted: select() failed", fr->fs_path);
            state = STATE_ERROR;
            break;
        }

        if (select_status == 0) 
        {
            /* select() timeout */

            if (BufferLength(fr->clientOutputBuffer)) 
            {
                if (fr->role == FCGIENC_RESPONDER)
                {
                    client_send = TRUE;
                }
            }
            else if (dynamic_first_recv) 
            {
                struct timeval qwait;

                fcgienc_util_ticks(&fr->queueTime);
                timersub(&fr->queueTime, &fr->startTime, &qwait);

                send_to_pm(FCGIENC_REQUEST_TIMEOUT_JOB, fr->fs_path, fr->user, fr->group, 0, 0);

                dynamic_first_recv = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                continue;
            }
            else 
            {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: comm with "
                    "server \"%s\" aborted: idle timeout (%d sec)",
                    fr->fs_path, idle_timeout);
                state = STATE_ERROR;
            }
        }

        if (FD_ISSET(fr->fd, &write_set))
        {
            /* send to the server */

            rv = fcgienc_buf_socket_send(fr->serverOutputBuffer, fr->fd);

            if (rv < 0)
            {
                ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                    "\"%s\" aborted: write failed", fr->fs_path);
                state = STATE_ERROR;
                break;
            }
        } 

        if (FD_ISSET(fr->fd, &read_set)) 
        {
            /* recv from the server */

            if (dynamic_first_recv) 
            {
                dynamic_first_recv = 0;
                fcgienc_util_ticks(&fr->queueTime);
            }

            rv = fcgienc_buf_socket_recv(fr->serverInputBuffer, fr->fd);

            if (rv < 0) 
            {
                ap_log_rerror(FCGIENC_LOG_ERR, r, "FastCGIENC: comm with server "
                    "\"%s\" aborted: read failed", fr->fs_path);
                state = STATE_ERROR;
                break;
            }

            if (rv == 0) 
            {
                fr->keepReadingFromFcgiApp = FALSE;
                state = STATE_CLIENT_SEND;
                break;
            }
        }

        if (fcgienc_protocol_dequeue(rp, fr)) 
        {
            state = STATE_ERROR;
            break;
        }
        
        if (fr->parseHeader == SCAN_CGI_READING_HEADERS) 
        {
            const char * err = process_headers(r, fr);
            if (err)
            {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                    "FastCGIENC: comm with server \"%s\" aborted: "
                    "error parsing headers: %s", fr->fs_path, err);
                state = STATE_ERROR;
                break;
            }
        }

        if (fr->exitStatusSet) 
        {
            fr->keepReadingFromFcgiApp = FALSE;
            state = STATE_CLIENT_SEND;
            break;
        }
    }
    
    return (state == STATE_ERROR);
}


/*----------------------------------------------------------------------
 * This is the core routine for moving data between the FastCGIENC
 * application and the Web server's client.
 */
static int do_work(request_rec * const r, fcgienc_request * const fr)
{
    int rv;
    pool *rp = r->pool;

    fcgienc_protocol_queue_begin_request(fr);

    if (fr->role == FCGIENC_RESPONDER) 
    {
        rv = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
        if (rv != OK) 
        {
            ap_kill_timeout(r);
            return rv;
        }

        fr->expectingClientContent = ap_should_client_block(r);
    }

    ap_block_alarms();
    ap_register_cleanup(rp, (void *)fr, cleanup, ap_null_cleanup);
    ap_unblock_alarms();

#ifdef WIN32
    if (fr->using_npipe_io)
    {
        rv = npipe_io(fr);
    }
    else
#endif
    {
        rv = socket_io(fr);
    }

    /* comm with the server is done */
    close_connection_to_fs(fr);

    if (fr->role == FCGIENC_RESPONDER) 
    {
        sink_client_data(fr);
    }

    while (rv == 0 && (BufferLength(fr->serverInputBuffer) || BufferLength(fr->clientOutputBuffer)))
    {
        if (fcgienc_protocol_dequeue(rp, fr)) 
        {
            rv = HTTP_INTERNAL_SERVER_ERROR;
        }
    
        if (fr->parseHeader == SCAN_CGI_READING_HEADERS) 
        {
            const char * err = process_headers(r, fr);
            if (err)
            {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
                    "FastCGIENC: comm with server \"%s\" aborted: "
                    "error parsing headers: %s", fr->fs_path, err);
                rv = HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (fr->role == FCGIENC_RESPONDER) 
        {
            if (write_to_client(fr)) 
            {
                break;
            }
        }
        else
        {
            fcgienc_buf_reset(fr->clientOutputBuffer);
        }
    }

    switch (fr->parseHeader) 
    {
    case SCAN_CGI_FINISHED:

        if (fr->role == FCGIENC_RESPONDER) 
        {
            /* RUSSIAN_APACHE requires rflush() over bflush() */
            ap_rflush(r);
#ifndef APACHE2
            ap_bgetopt(r->connection->client, BO_BYTECT, &r->bytes_sent);
#endif
        }

        /* fall through */

    case SCAN_CGI_INT_REDIRECT:
    case SCAN_CGI_SRV_REDIRECT:

        break;

    case SCAN_CGI_READING_HEADERS:

        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: incomplete headers "
            "(%d bytes) received from server \"%s\"", fr->header->nelts, fr->fs_path);
        
        /* fall through */

    case SCAN_CGI_BAD_HEADER:

        rv = HTTP_INTERNAL_SERVER_ERROR;
        break;

    default:

        ASSERT(0);
        rv = HTTP_INTERNAL_SERVER_ERROR;
    }
   
    ap_kill_timeout(r);
    return rv;
}

static int 
create_fcgienc_request(request_rec * const r, 
                    const char * const path, 
                    fcgienc_request ** const frP)
{
    const char *fs_path;
    pool * const p = r->pool;
    fcgienc_server *fs;
    fcgienc_request * const fr = (fcgienc_request *)ap_pcalloc(p, sizeof(fcgienc_request));
    uid_t uid;
    gid_t gid;

    fs_path = path ? path : r->filename;

    get_request_identity(r, &uid, &gid);

    fs = fcgienc_util_fs_get_by_id(fs_path, uid, gid);

    if (fs == NULL) 
    {
        const char * err;
        struct stat *my_finfo;

        /* dynamic? */
        
#ifndef APACHE2
        if (path == NULL) 
        {
            /* AP2: its bogus that we don't make use of r->finfo, but 
             * its an apr_finfo_t and there is no apr_os_finfo_get() */

            my_finfo = &r->finfo;
        }
        else
#endif
        {
            my_finfo = (struct stat *) ap_palloc(p, sizeof(struct stat));
            
            if (stat(fs_path, my_finfo) < 0) 
            {
                ap_log_rerror(FCGIENC_LOG_ERR_ERRNO, r, 
                    "FastCGIENC: stat() of \"%s\" failed", fs_path);
                return HTTP_NOT_FOUND;
            }
        }

        err = fcgienc_util_fs_is_path_ok(p, fs_path, my_finfo);
        if (err) 
        {
            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, 
                "FastCGIENC: invalid (dynamic) server \"%s\": %s", fs_path, err);
            return HTTP_FORBIDDEN;
        }
    }

    fr->nph = (strncmp(strrchr(fs_path, '/'), "/nph-", 5) == 0)
		|| (fs && fs->nph);

    fr->serverInputBuffer = fcgienc_buf_new(p, SERVER_BUFSIZE);
    fr->serverOutputBuffer = fcgienc_buf_new(p, SERVER_BUFSIZE);
    fr->clientInputBuffer = fcgienc_buf_new(p, SERVER_BUFSIZE);
    fr->clientOutputBuffer = fcgienc_buf_new(p, SERVER_BUFSIZE);
    fr->erBufPtr = fcgienc_buf_new(p, sizeof(FCGIENC_EndRequestBody) + 1);
    fr->gotHeader = FALSE;
    fr->parseHeader = SCAN_CGI_READING_HEADERS;
    fr->header = ap_make_array(p, 1, 1);
    fr->fs_stderr = NULL;
    fr->r = r;
    fr->readingEndRequestBody = FALSE;
    fr->exitStatus = 0;
    fr->exitStatusSet = FALSE;
    fr->requestId = 1; /* anything but zero is OK here */
    fr->eofSent = FALSE;
    fr->role = FCGIENC_RESPONDER;
    fr->expectingClientContent = FALSE;
    fr->keepReadingFromFcgiApp = TRUE;
    fr->fs = fs;
    fr->fs_path = fs_path;
    fr->authHeaders = ap_make_table(p, 10);
#ifdef WIN32
    fr->fd = INVALID_SOCKET;
    fr->dynamic = ((fs == NULL) || (fs->directive == APP_CLASS_DYNAMIC)) ? TRUE : FALSE;
    fr->using_npipe_io = (! fr->dynamic && (fs->dest_addr || fs->socket_addr)) ? 0 : 1;
#else
    fr->dynamic = (fs == NULL) ? TRUE : FALSE;
    fr->fd = -1;
#endif

    if (fr->nph) {
#ifdef APACHE2    
		struct ap_filter_t *cur;

		fr->parseHeader = SCAN_CGI_FINISHED;

		/* remove the filters up through protocol - since the headers
		 * haven't been parsed, there is no way they can work */

		cur = r->proto_output_filters;
		while (cur && cur->frec->ftype < AP_FTYPE_CONNECTION) {
			cur = cur->next;
		}
		r->output_filters = r->proto_output_filters = cur;
#else
	    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, 
	        "FastCGIENC: invalid request \"%s\": non parsed header support is "
	    		"not available in Apache13 (patch welcome)", fs_path);
	    return HTTP_FORBIDDEN;
#endif    
	}

    set_uid_n_gid(r, &fr->user, &fr->group);

    *frP = fr;

    return OK;
}

/*
 *----------------------------------------------------------------------
 *
 * handler --
 *
 *      This routine gets called for a request that corresponds to
 *      a FastCGIENC connection.  It performs the request synchronously.
 *
 * Results:
 *      Final status of request: OK or NOT_FOUND or HTTP_INTERNAL_SERVER_ERROR.
 *
 * Side effects:
 *      Request performed.
 *
 *----------------------------------------------------------------------
 */

/* Stolen from mod_cgi.c..
 * KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */
static int apache_is_scriptaliased(request_rec *r)
{
    const char *t = ap_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

/* If a script wants to produce its own Redirect body, it now
 * has to explicitly *say* "Status: 302".  If it wants to use
 * Apache redirects say "Status: 200".  See process_headers().
 */
static int post_process_for_redirects(request_rec * const r,
    const fcgienc_request * const fr)
{
    switch(fr->parseHeader) {
        case SCAN_CGI_INT_REDIRECT:

            /* @@@ There are still differences between the handling in
             * mod_cgi and mod_encrypt.  This needs to be revisited.
             */
            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            r->method = "GET";
            r->method_number = M_GET;
            ap_table_unset(r->headers_in, "Content-length");

            ap_internal_redirect_handler(ap_table_get(r->headers_out, "Location"), r);
            return OK;

        case SCAN_CGI_SRV_REDIRECT:
            return HTTP_MOVED_TEMPORARILY;

        default:
            return OK;
    }
}

/******************************************************************************
 * Process encrypt-script requests.  Based on mod_cgi::cgi_handler().
 */
static int content_handler(request_rec *r)
{
    fcgienc_request *fr = NULL;
    int ret;

#ifdef APACHE2
    if (strcmp(r->handler, ENCRYPT_HANDLER_NAME))
        return DECLINED;
#endif

	/* log session start */
	if (r->the_request)
		log_message(ENCRYPT_LOG_INFO, "Session Starting : %s", r->the_request);

    /* Setup a new FastCGIENC request */
    ret = create_fcgienc_request(r, NULL, &fr);
    if (ret)
		goto HANDLER_EXIT;

    /* If its a dynamic invocation, make sure scripts are OK here */
    if (fr->dynamic && ! (ap_allow_options(r) & OPT_EXECCGI) 
        && ! apache_is_scriptaliased(r)) 
    {
        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
            "FastCGIENC: \"ExecCGI Option\" is off in this directory: %s", r->uri);
		ret = HTTP_FORBIDDEN;
		goto HANDLER_EXIT;
    }

	if (fcgienc_encrypt_flag == TRUE)
	{
		if (InitEncrypt(&fr->encryptor) != 0)
		{
			log_message(ENCRYPT_LOG_INFO, "Failed to init encrypt module");
			ret = HTTP_SERVICE_UNAVAILABLE;
			goto HANDLER_EXIT;
		}
	}

    /* Process the encrypt-script request */
    if ((ret = do_work(r, fr)) != OK)
        goto HANDLER_EXIT;

    /* Special case redirects */
    ret = post_process_for_redirects(r, fr);

HANDLER_EXIT:
	if (fcgienc_encrypt_flag == TRUE)
		CloseCrypt(&fr->encryptor);

	if (fcgienc_decrypt_flag == TRUE)
		CloseCrypt(&fr->decryptor);

	if (r->the_request)
	{
		log_message(ENCRYPT_LOG_INFO, "Session Ended : %s", r->the_request);
	}

    return ret;
}


static int post_process_auth_passed_header(table *t, const char *key, const char * const val)
{
    if (strncasecmp(key, "Variable-", 9) == 0)
        key += 9;

    ap_table_setn(t, key, val);
    return 1;
}

static int post_process_auth_passed_compat_header(table *t, const char *key, const char * const val)
{
    if (strncasecmp(key, "Variable-", 9) == 0)
        ap_table_setn(t, key + 9, val);

    return 1;
}

static int post_process_auth_failed_header(table * const t, const char * const key, const char * const val)
{
    ap_table_setn(t, key, val);
    return 1;
}

static void post_process_auth(fcgienc_request * const fr, const int passed)
{
    request_rec * const r = fr->r;

    /* Restore the saved subprocess_env because we muddied ours up */
    r->subprocess_env = fr->saved_subprocess_env;

    if (passed) {
        if (fr->auth_compat) {
            ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_passed_compat_header,
                 (void *)r->subprocess_env, fr->authHeaders, NULL);
        }
        else {
            ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_passed_header,
                 (void *)r->subprocess_env, fr->authHeaders, NULL);
        }
    }
    else {
        ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_failed_header,
             (void *)r->err_headers_out, fr->authHeaders, NULL);
    }

    /* @@@ Restore these.. its a hack until I rewrite the header handling */
    r->status = HTTP_OK;
    r->status_line = NULL;
}

static int check_user_authentication(request_rec *r)
{
    int res, authenticated = 0;
    const char *password;
    fcgienc_request *fr;
    const fcgienc_dir_config * const dir_config =
        (const fcgienc_dir_config *)ap_get_module_config(r->per_dir_config, &encrypt_module);

    if (dir_config->authenticator == NULL)
        return DECLINED;

    /* Get the user password */
    if ((res = ap_get_basic_auth_pw(r, &password)) != OK)
        return res;

    res = create_fcgienc_request(r, dir_config->authenticator, &fr);
    if (res)
    {
        return res;
    }

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "REMOTE_PASSWD", password);
    ap_table_setn(r->subprocess_env, "FCGIENC_APACHE_ROLE", "AUTHENTICATOR");

    /* The FastCGIENC Protocol doesn't differentiate authentication */
    fr->role = FCGIENC_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->authenticator_options & FCGIENC_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AuthenticationFailed;

    authenticated = (r->status == 200);
    post_process_auth(fr, authenticated);

    /* A redirect shouldn't be allowed during the authentication phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
            "FastCGIENC: FastCgiEncAuthenticator \"%s\" redirected (not allowed)",
            dir_config->authenticator);
        goto AuthenticationFailed;
    }

    if (authenticated)
        return OK;

AuthenticationFailed:
    if (!(dir_config->authenticator_options & FCGIENC_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_note_basic_auth_failure(r);
    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
        "FastCGIENC: authentication failed for user \"%s\": %s",
#ifdef APACHE2
        r->user, r->uri);
#else
        r->connection->user, r->uri);
#endif

        return (res == OK) ? HTTP_UNAUTHORIZED : res;
}

static int check_user_authorization(request_rec *r)
{
    int res, authorized = 0;
    fcgienc_request *fr;
    const fcgienc_dir_config * const dir_config =
        (const fcgienc_dir_config *)ap_get_module_config(r->per_dir_config, &encrypt_module);

    if (dir_config->authorizer == NULL)
        return DECLINED;

    /* @@@ We should probably honor the existing parameters to the require directive
     * as well as allow the definition of new ones (or use the basename of the
     * FastCGIENC server and pass the rest of the directive line), but for now keep
     * it simple. */

    res = create_fcgienc_request(r, dir_config->authorizer, &fr);
    if (res)
    {
        return res;
    }

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "FCGIENC_APACHE_ROLE", "AUTHORIZER");

    fr->role = FCGIENC_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->authorizer_options & FCGIENC_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AuthorizationFailed;

    authorized = (r->status == 200);
    post_process_auth(fr, authorized);

    /* A redirect shouldn't be allowed during the authorization phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
            "FastCGIENC: FastCgiEncAuthorizer \"%s\" redirected (not allowed)",
            dir_config->authorizer);
        goto AuthorizationFailed;
    }

    if (authorized)
        return OK;

AuthorizationFailed:
    if (!(dir_config->authorizer_options & FCGIENC_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_note_basic_auth_failure(r);
    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
        "FastCGIENC: authorization failed for user \"%s\": %s", 
#ifdef APACHE2
        r->user, r->uri);
#else
        r->connection->user, r->uri);
#endif

    return (res == OK) ? HTTP_UNAUTHORIZED : res;
}

static int check_access(request_rec *r)
{
    int res, access_allowed = 0;
    fcgienc_request *fr;
    const fcgienc_dir_config * const dir_config =
        (fcgienc_dir_config *)ap_get_module_config(r->per_dir_config, &encrypt_module);

    if (dir_config == NULL || dir_config->access_checker == NULL)
        return DECLINED;

    res = create_fcgienc_request(r, dir_config->access_checker, &fr);
    if (res)
    {
        return res;
    }

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "FCGIENC_APACHE_ROLE", "ACCESS_CHECKER");

    /* The FastCGIENC Protocol doesn't differentiate access control */
    fr->role = FCGIENC_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->access_checker_options & FCGIENC_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AccessFailed;

    access_allowed = (r->status == 200);
    post_process_auth(fr, access_allowed);

    /* A redirect shouldn't be allowed during the access check phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r,
            "FastCGIENC: FastCgiEncAccessChecker \"%s\" redirected (not allowed)",
            dir_config->access_checker);
        goto AccessFailed;
    }

    if (access_allowed)
        return OK;

AccessFailed:
    if (!(dir_config->access_checker_options & FCGIENC_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, r, "FastCGIENC: access denied: %s", r->uri);
    return (res == OK) ? HTTP_FORBIDDEN : res;
}

static int 
fixups(request_rec * r)
{
    if (r->filename) {
        uid_t uid;
        gid_t gid;

        get_request_identity(r, &uid, &gid);

	    if (fcgienc_util_fs_get_by_id(r->filename, uid, gid))
	    {
	        r->handler = ENCRYPT_HANDLER_NAME;
	        return OK;
	    }
    }

    return DECLINED;
}

#ifndef APACHE2

# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE1, help }
# define AP_INIT_TAKE12(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE12, help }
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, FLAG, help }

#endif

static const command_rec encrypt_cmds[] = 
{
    AP_INIT_RAW_ARGS("AppClass",      fcgienc_config_new_static_server, NULL, RSRC_CONF, NULL),
    AP_INIT_RAW_ARGS("FastCgiEncServer", fcgienc_config_new_static_server, NULL, RSRC_CONF, NULL),

    AP_INIT_RAW_ARGS("ExternalAppClass",      fcgienc_config_new_external_server, NULL, RSRC_CONF, NULL),
    AP_INIT_RAW_ARGS("FastCgiEncExternalServer", fcgienc_config_new_external_server, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncIpcDir", fcgienc_config_set_socket_dir, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncSuexec",  fcgienc_config_set_wrapper, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncWrapper", fcgienc_config_set_wrapper, NULL, RSRC_CONF, NULL),

    AP_INIT_RAW_ARGS("FCGIConfig",    fcgienc_config_set_config, NULL, RSRC_CONF, NULL),
    AP_INIT_RAW_ARGS("FastCgiEncConfig", fcgienc_config_set_config, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE12("FastCgiEncAuthenticator", fcgienc_config_new_auth_server,
        (void *)FCGIENC_AUTH_TYPE_AUTHENTICATOR, ACCESS_CONF,
        "a encrypt-script path (absolute or relative to ServerRoot) followed by an optional -compat"),
    AP_INIT_FLAG("FastCgiEncAuthenticatorAuthoritative", fcgienc_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgienc_dir_config, authenticator_options), ACCESS_CONF,
        "Set to 'off' to allow authentication to be passed along to lower modules upon failure"),

    AP_INIT_TAKE12("FastCgiEncAuthorizer", fcgienc_config_new_auth_server,
        (void *)FCGIENC_AUTH_TYPE_AUTHORIZER, ACCESS_CONF,
        "a encrypt-script path (absolute or relative to ServerRoot) followed by an optional -compat"),
    AP_INIT_FLAG("FastCgiEncAuthorizerAuthoritative", fcgienc_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgienc_dir_config, authorizer_options), ACCESS_CONF,
        "Set to 'off' to allow authorization to be passed along to lower modules upon failure"),

    AP_INIT_TAKE12("FastCgiEncAccessChecker", fcgienc_config_new_auth_server,
        (void *)FCGIENC_AUTH_TYPE_ACCESS_CHECKER, ACCESS_CONF,
        "a encrypt-script path (absolute or relative to ServerRoot) followed by an optional -compat"),
    AP_INIT_FLAG("FastCgiEncAccessCheckerAuthoritative", fcgienc_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgienc_dir_config, access_checker_options), ACCESS_CONF,
        "Set to 'off' to allow access control to be passed along to lower modules upon failure"),

    AP_INIT_TAKE2("FastCgiEncLogpath",  fcgienc_config_set_logpath, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncMemcachedServer",  fcgienc_config_set_memcached, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncEncrypt",  fcgienc_config_set_encrypt, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncDecrypt",  fcgienc_config_set_decrypt, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncAuthServer",  fcgienc_config_set_authserver, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncMasterKeyServer",  fcgienc_config_set_masterkeyserver, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncDataKeyServer",  fcgienc_config_set_datakeyserver, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncKeyString",  fcgienc_config_set_keystring, NULL, RSRC_CONF, NULL),

    AP_INIT_TAKE1("FastCgiEncUserName",  fcgienc_config_set_username, NULL, RSRC_CONF, NULL),
    AP_INIT_TAKE1("FastCgiEncPassword",  fcgienc_config_set_password, NULL, RSRC_CONF, NULL),

    { NULL }
};

#ifdef APACHE2

static void register_hooks(apr_pool_t * p)
{
    /* ap_hook_pre_config(x_pre_config, NULL, NULL, APR_HOOK_MIDDLE); */
    ap_hook_post_config(init_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(fcgienc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(content_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(check_user_authentication, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(check_access, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(check_user_authorization, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(fixups, NULL, NULL, APR_HOOK_MIDDLE); 
}

module AP_MODULE_DECLARE_DATA encrypt_module =
{
    STANDARD20_MODULE_STUFF,
    fcgienc_config_create_dir_config,  /* per-directory config creator */
    NULL,                           /* dir config merger */
    NULL,                           /* server config creator */
    NULL,                           /* server config merger */
    encrypt_cmds,                   /* command table */
    register_hooks,                 /* set up other request processing hooks */
};

#else /* !APACHE2 */

handler_rec encrypt_handlers[] = {
    { FCGIENC_MAGIC_TYPE, content_handler },
    { ENCRYPT_HANDLER_NAME, content_handler },
    { NULL }
};

module MODULE_VAR_EXPORT encrypt_module = {
    STANDARD_MODULE_STUFF,
    init_module,              /* initializer */
    fcgienc_config_create_dir_config,    /* per-dir config creator */
    NULL,                      /* per-dir config merger (default: override) */
    NULL,                      /* per-server config creator */
    NULL,                      /* per-server config merger (default: override) */
    encrypt_cmds,              /* command table */
    encrypt_handlers,          /* [9] content handlers */
    NULL,                      /* [2] URI-to-filename translation */
    check_user_authentication, /* [5] authenticate user_id */
    check_user_authorization,  /* [6] authorize user_id */
    check_access,              /* [4] check access (based on src & http headers) */
    NULL,                      /* [7] check/set MIME type */
    fixups,                    /* [8] fixups */
    NULL,                      /* [10] logger */
    NULL,                      /* [3] header-parser */
    fcgienc_child_init,           /* process initialization */
#ifdef WIN32
    fcgienc_child_exit,           /* process exit/cleanup */
#else
    NULL,
#endif
    NULL                       /* [1] post read-request handling */
};

#endif /* !APACHE2 */
