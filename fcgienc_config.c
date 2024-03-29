/*
 * Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#define CORE_PRIVATE
#include "fcgienc.h"
#include "fcgienc_log.h"

#ifdef APACHE2

#include <limits.h>
#include "mpm_common.h"     /* ap_uname2id, ap_gname2id */

#ifdef WIN32
#include <direct.h>
#else
#include <unistd.h>
#include "unixd.h"
#endif

#endif

#ifdef WIN32
/* warning C4100: unreferenced formal parameter */
/* warning C4706: assignment within conditional expression */ 
#pragma warning( disable : 4100 4706 )
#endif

/*******************************************************************************
 * Get the next configuration directive argument, & return an in_addr and port.
 * The arg must be in the form "host:port" where host can be an IP or hostname.
 * The pool arg should be persistant storage.
 */
static const char *get_host_n_port(pool *p, const char **arg,
        const char **host, u_short *port)
{
    char *cvptr, *portStr;
    long tmp;

    *host = ap_getword_conf(p, arg);
    if (**host == '\0')
        return "\"\"";

    portStr = strchr(*host, ':');
    if (portStr == NULL)
        return "missing port specification";

    /* Split the host and port portions */
    *portStr++ = '\0';

    /* Convert port number */
    tmp = (u_short) strtol(portStr, &cvptr, 10);
    if (*cvptr != '\0' || tmp < 1 || tmp > USHRT_MAX)
        return ap_pstrcat(p, "bad port number \"", portStr, "\"", NULL);

    *port = (unsigned short) tmp;

    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_short.
 * The pool arg should be temporary storage.
 */
static const char *get_u_short(pool *p, const char **arg,
        u_short *num, u_short min)
{
    char *ptr;
	long tmp;
    const char *txt = ap_getword_conf(p, arg);

    if (*txt == '\0') {
		return "\"\"";
	}

    tmp = strtol(txt, &ptr, 10);

    if (*ptr != '\0') {
        return ap_pstrcat(p, "\"", txt, "\" must be a positive integer", NULL);
	}
    
	if (tmp < min || tmp > USHRT_MAX) {
        return ap_psprintf(p, "\"%u\" must be >= %u and < %u", *num, min, USHRT_MAX);
	}

	*num = (u_short) tmp;

    return NULL;
}

static const char *get_int(pool *p, const char **arg, int *num, int min)
{
    char *cp;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
    {
        return "\"\"";
    }

    *num = (int) strtol(val, &cp, 10);

    if (*cp != '\0')
    {
        return ap_pstrcat(p, "can't parse ", "\"", val, "\"", NULL);
    }
    else if (*num < min)
    {
        return ap_psprintf(p, "\"%d\" must be >= %d", *num, min);
    }
            
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_int.
 * The pool arg should be temporary storage.
 */
static const char *get_u_int(pool *p, const char **arg,
        u_int *num, u_int min)
{
    char *ptr;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    *num = (u_int)strtol(val, &ptr, 10);

    if (*ptr != '\0')
        return ap_pstrcat(p, "\"", val, "\" must be a positive integer", NULL);
    else if (*num < min)
        return ap_psprintf(p, "\"%u\" must be >= %u", *num, min);
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return a float.
 * The pool arg should be temporary storage.
 */
static const char *get_float(pool *p, const char **arg,
        float *num, float min, float max)
{
    char *ptr;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    *num = (float) strtod(val, &ptr);

    if (*ptr != '\0')
        return ap_pstrcat(p, "\"", val, "\" is not a floating point number", NULL);
    if (*num < min || *num > max)
        return ap_psprintf(p, "\"%f\" is not between %f and %f", *num, min, max);
    return NULL;
}

const char *fcgienc_config_set_env_var(pool *p, char **envp, unsigned int *envc, char * var)
{
    if (*envc >= MAX_INIT_ENV_VARS) {
        return "too many variables, must be <= MAX_INIT_ENV_VARS";
    }

    if (strchr(var, '=') == NULL) {
        *(envp + *envc) = ap_pstrcat(p, var, "=", getenv(var), NULL);
    }
    else {
        *(envp + *envc) = var;
    }

    (*envc)++;

    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & add it to an env array.
 * The pool arg should be permanent storage.
 */
static const char *get_env_var(pool *p, const char **arg, char **envp, unsigned int *envc)
{
    char * const val = ap_getword_conf(p, arg);

    if (*val == '\0') {
        return "\"\"";
    }

    return fcgienc_config_set_env_var(p, envp, envc, val);
}

static const char *get_pass_header(pool *p, const char **arg, array_header **array)
{
    const char **header;

    if (!*array) {
        *array = ap_make_array(p, 10, sizeof(char*));
    }

    header = (const char **)ap_push_array(*array);
    *header = ap_getword_conf(p, arg);

    return header ? NULL : "\"\"";
}

/*******************************************************************************
 * Return a "standard" message for common configuration errors.
 */
static const char *invalid_value(pool *p, const char *cmd, const char *id,
        const char *opt, const char *err)
{
    return ap_psprintf(p, "%s%s%s: invalid value for %s: %s",
                    cmd, id ? " " : "", id ? id : "",  opt, err);
}

/*******************************************************************************
 * Set/Reset the uid/gid that Apache and the PM will run as.  This is ap_user_id
 * and ap_group_id if we're started as root, and euid/egid otherwise.  Also try
 * to check that the config files don't set the User/Group after a FastCGIENC
 * directive is used that depends on it.
 */
/*@@@ To be complete, we should save a handle to the server each AppClass is
 * configured in and at init() check that the user/group is still what we
 * thought it was.  Also the other directives should only be allowed in the
 * parent Apache server.
 */
const char *fcgienc_config_set_fcgienc_uid_n_gid(int set)
{
    static int isSet = 0;

#ifndef WIN32

    uid_t uid = geteuid();
    gid_t gid = getegid();

    if (set == 0) {
        isSet = 0;
        fcgienc_user_id = (uid_t)-1;
        fcgienc_group_id = (gid_t)-1;
        return NULL;
    }

    if (uid == 0) {
        uid = ap_user_id;
    }

    if (gid == 0) {
        gid = ap_group_id;
    }

    if (isSet && (uid != fcgienc_user_id || gid != fcgienc_group_id)) {
        return "User/Group commands must preceed FastCGIENC server definitions";
    }

    isSet = 1;
    fcgienc_user_id = uid;
    fcgienc_group_id = gid;

#endif /* !WIN32 */

    return NULL;
}

apcb_t fcgienc_config_reset_globals(void* dummy)
{
    fcgienc_config_pool = NULL;
    fcgienc_servers = NULL;
    fcgienc_config_set_fcgienc_uid_n_gid(0);
    fcgienc_wrapper = NULL;
    fcgienc_socket_dir = NULL;
    
    fcgienc_dynamic_total_proc_count = 0;
    fcgienc_dynamic_epoch = 0;
    fcgienc_dynamic_last_analyzed = 0;

    dynamicMaxProcs = FCGIENC_DEFAULT_MAX_PROCS;
    dynamicMinProcs = FCGIENC_DEFAULT_MIN_PROCS;
    dynamicMaxClassProcs = FCGIENC_DEFAULT_MAX_CLASS_PROCS;
    dynamicKillInterval = FCGIENC_DEFAULT_KILL_INTERVAL;
    dynamicUpdateInterval = FCGIENC_DEFAULT_UPDATE_INTERVAL;
    dynamicGain = FCGIENC_DEFAULT_GAIN;
    dynamicThreshold1 = FCGIENC_DEFAULT_THRESHOLD_1;
    dynamicThresholdN = FCGIENC_DEFAULT_THRESHOLD_N;
    dynamicPleaseStartDelay = FCGIENC_DEFAULT_START_PROCESS_DELAY;
    dynamicAppConnectTimeout = FCGIENC_DEFAULT_APP_CONN_TIMEOUT;
    dynamicEnvp = &fcgienc_empty_env;
    dynamicProcessSlack = FCGIENC_DEFAULT_PROCESS_SLACK;
    dynamicAutoRestart = FCGIENC_DEFAULT_RESTART_DYNAMIC;
    dynamicAutoUpdate = FCGIENC_DEFAULT_AUTOUPDATE;
    dynamicListenQueueDepth = FCGIENC_DEFAULT_LISTEN_Q;
    dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
    dynamicRestartDelay = FCGIENC_DEFAULT_RESTART_DELAY;
    dynamicMinServerLife = FCGIENC_DEFAULT_MIN_SERVER_LIFE;
    dynamic_pass_headers = NULL;
    dynamic_idle_timeout = FCGIENC_DEFAULT_IDLE_TIMEOUT;
	dynamicFlush = FCGIENC_FLUSH;

#ifndef WIN32
	/* Close any old pipe (HUP/USR1) */
	if (fcgienc_pm_pipe[0] != -1) {
		close(fcgienc_pm_pipe[0]);
		fcgienc_pm_pipe[0] = -1;
	}
	if (fcgienc_pm_pipe[1] != -1) {
		close(fcgienc_pm_pipe[1]);
		fcgienc_pm_pipe[1] = -1;
	}
#endif

    return APCB_OK;
}

/*******************************************************************************
 * Create a file to hold fastcgienc encrypt log.
 */
const char *fcgienc_config_make_logfile(pool *tp, char *path)
{
    struct stat finfo;
	apr_status_t rv; 

    /* Is the directory spec'd correctly */
#ifndef WIN32
    if (*path != '/') {
        return "path is not absolute (it must start with a \"/\")";
    }
    else {
        int i = strlen(path) - 1;

        /* Strip trailing "/"s */
        while(i > 0 && path[i] == '/') path[i--] = '\0';
    }
#endif

    /* Does it exist? */
    if (stat(path, &finfo) == 0) {
		/* Yes, is it a directory? */
		if (S_ISDIR(finfo.st_mode))
			return "is a directory!";
	}

    /* No, but maybe we can create it */
	if ((rv = apr_file_open(&fcgienc_logfp, fcgienc_logpath, \
		APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_APPEND | APR_FOPEN_XTHREAD | 0, \
		APR_OS_DEFAULT, tp)) != APR_SUCCESS)
    {
        return ap_psprintf(tp,
            "doesn't exist and can't be created: %s",
            strerror(errno));
    }

#ifndef WIN32
    /* If we're root, we're gonna setuid/setgid so we need to chown */
    if (geteuid() == 0 && chown(path, ap_user_id, ap_group_id) != 0) {
        return ap_psprintf(tp,
            "can't chown() to the server (uid %ld, gid %ld): %s",
            (long)ap_user_id, (long)ap_group_id, strerror(errno));
    }
#endif

    return NULL;
}

/*******************************************************************************
 * Create a directory to hold Unix/Domain sockets.
 */
const char *fcgienc_config_make_dir(pool *tp, char *path)
{
    struct stat finfo;
    const char *err = NULL;

    /* Is the directory spec'd correctly */
    if (*path != '/') {
        return "path is not absolute (it must start with a \"/\")";
    }
    else {
        int i = strlen(path) - 1;

        /* Strip trailing "/"s */
        while(i > 0 && path[i] == '/') path[i--] = '\0';
    }

    /* Does it exist? */
    if (stat(path, &finfo) != 0) {
        /* No, but maybe we can create it */
#ifdef WIN32
        if (mkdir(path) != 0) 
#else
        if (mkdir(path, S_IRWXU) != 0)
#endif
        {
            return ap_psprintf(tp,
                "doesn't exist and can't be created: %s",
                strerror(errno));
        }

#ifndef WIN32
        /* If we're root, we're gonna setuid/setgid so we need to chown */
        if (geteuid() == 0 && chown(path, ap_user_id, ap_group_id) != 0) {
            return ap_psprintf(tp,
                "can't chown() to the server (uid %ld, gid %ld): %s",
                (long)ap_user_id, (long)ap_group_id, strerror(errno));
        }
#endif
    }
    else {
        /* Yes, is it a directory? */
        if (!S_ISDIR(finfo.st_mode))
            return "isn't a directory!";

        /* Can we RWX in there? */
#ifdef WIN32
        err = fcgienc_util_check_access(tp, NULL, &finfo, _S_IREAD | _S_IWRITE | _S_IEXEC, fcgienc_user_id, fcgienc_group_id);
#else
        err = fcgienc_util_check_access(tp, NULL, &finfo, R_OK | W_OK | X_OK,
                          fcgienc_user_id, fcgienc_group_id);
#endif
        if (err != NULL) {
            return ap_psprintf(tp,
                "access for server (uid %ld, gid %ld) failed: %s",
                (long)fcgienc_user_id, (long)fcgienc_group_id, err);
        }
    }
    return NULL;
}

/*******************************************************************************
 * Create a "dynamic" subdirectory.  If the directory
 * already exists we don't mess with it unless 'wax' is set.
 */
#ifndef WIN32
const char *fcgienc_config_make_dynamic_dir(pool *p, const int wax)
{
    const char *err;
    pool *tp;

    fcgienc_dynamic_dir = ap_pstrcat(p, fcgienc_socket_dir, "/dynamic", NULL);

    if ((err = fcgienc_config_make_dir(p, fcgienc_dynamic_dir)))
        return ap_psprintf(p, "can't create dynamic directory \"%s\": %s", fcgienc_dynamic_dir, err);

    /* Don't step on a running server unless its OK. */
    if (!wax)
        return NULL;

#ifdef APACHE2
    {
        apr_dir_t * dir;
        apr_finfo_t finfo;

        if (apr_pool_create(&tp, p))
            return "apr_pool_create() failed";

        if (apr_dir_open(&dir, fcgienc_dynamic_dir, tp))
            return "apr_dir_open() failed";

        /* delete the contents */

        while (apr_dir_read(&finfo, APR_FINFO_NAME, dir) == APR_SUCCESS)
        {
            if (strcmp(finfo.name, ".") == 0 || strcmp(finfo.name, "..") == 0)
                continue;

            apr_file_remove(finfo.name, tp);
        }
    }

#else /* !APACHE2 */
    {
        DIR *dp;
        struct dirent *dirp = NULL;

        tp = ap_make_sub_pool(p);

        dp = ap_popendir(tp, fcgienc_dynamic_dir);
        if (dp == NULL) {
            ap_destroy_pool(tp);
            return ap_psprintf(p, "can't open dynamic directory \"%s\": %s",
                fcgienc_dynamic_dir, strerror(errno));
        }

        /* delete the contents */

        while ((dirp = readdir(dp)) != NULL) 
        {
            if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
                continue;

            unlink(ap_pstrcat(tp, fcgienc_dynamic_dir, "/", dirp->d_name, NULL));
        }
    }

#endif /* !APACHE2 */

    ap_destroy_pool(tp);

    return NULL;
}
#endif

/*******************************************************************************
 * Change the directory used for the Unix/Domain sockets from the default.
 * Create the directory and the "dynamic" subdirectory.
 */
const char *fcgienc_config_set_socket_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    pool * const tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *err;
    char * arg_nc;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (fcgienc_socket_dir) {
        return ap_psprintf(tp, "%s %s: already defined as \"%s\"",
                        name, arg, fcgienc_socket_dir);
    }

    err = fcgienc_config_set_fcgienc_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgienc_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGIENC server definitions",
            name);
    }

    arg_nc = ap_pstrdup(cmd->pool, arg);

#ifndef WIN32

#ifdef APACHE2
    if (apr_filepath_merge(&arg_nc, "", arg, 0, cmd->pool))
        return ap_psprintf(tp, "%s %s: invalid filepath", name, arg);
#else
    arg_nc = ap_os_canonical_filename(cmd->pool, arg_nc);
#endif

    arg_nc = ap_server_root_relative(cmd->pool, arg_nc);

#else /* WIN32 */

	if (strncmp(arg_nc, "\\\\.\\pipe\\", 9) != 0)
		return ap_psprintf(tp, "%s %s is invalid format",name, arg_nc);

#endif

    fcgienc_socket_dir = arg_nc;

#ifdef WIN32
    fcgienc_dynamic_dir = ap_pstrcat(cmd->pool, fcgienc_socket_dir, "dynamic", NULL);
#else
    err = fcgienc_config_make_dir(tp, fcgienc_socket_dir);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg_nc, err);

    err = fcgienc_config_make_dynamic_dir(cmd->pool, 0);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg_nc, err);
#endif

    return NULL;
}

/*******************************************************************************
 * Enable, disable, or specify the path to a wrapper used to invoke all
 * FastCGIENC applications.
 */
const char *fcgienc_config_set_wrapper(cmd_parms *cmd, void *dummy, const char *arg)
{
#ifdef WIN32
    return ap_psprintf(cmd->temp_pool, 
        "the %s directive is not supported on WIN", cmd->cmd->name);
#else

    const char *err = NULL;
    const char * const name = cmd->cmd->name;
    pool * const tp = cmd->temp_pool;
    char * wrapper = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (fcgienc_wrapper)
    {
        return ap_psprintf(tp, "%s was already set to \"%s\"",
                           name, fcgienc_wrapper);
    }

    err = fcgienc_config_set_fcgienc_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgienc_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGIENC server definitions", name);
    }

    if (strcasecmp(arg, "Off") == 0) {
        fcgienc_wrapper = NULL;
        return NULL;
    }

    if (strcasecmp(arg, "On") == 0) 
    {
        wrapper = SUEXEC_BIN;
    }
    else
    {
#ifdef APACHE2
        if (apr_filepath_merge(&wrapper, "", arg, 0, cmd->pool))
            return ap_psprintf(tp, "%s %s: invalid filepath", name, arg);
#else
        wrapper = ap_os_canonical_filename(cmd->pool, (char *) arg);
#endif

        wrapper = ap_server_root_relative(cmd->pool, wrapper);
    }

    err = fcgienc_util_check_access(tp, wrapper, NULL, X_OK, fcgienc_user_id, fcgienc_group_id);
    if (err) 
    {
        return ap_psprintf(tp, "%s: \"%s\" execute access for server "
                           "(uid %ld, gid %ld) failed: %s", name, wrapper,
                           (long) fcgienc_user_id, (long) fcgienc_group_id, err);
    }

    fcgienc_wrapper = wrapper;

    return NULL;
#endif /* !WIN32 */
}

/*******************************************************************************
 * Configure a static FastCGIENC server.
 */
const char *fcgienc_config_new_static_server(cmd_parms *cmd, void *dummy, const char *arg)
{
    fcgienc_server *s;
    pool *p = cmd->pool, *tp = cmd->temp_pool;
    const char *name = cmd->cmd->name;
    char *fs_path = ap_getword_conf(p, &arg);
    const char *option, *err;

    /* Allocate temp storage for the array of initial environment variables */
    char **envp = ap_pcalloc(tp, sizeof(char *) * (MAX_INIT_ENV_VARS + 3));
    unsigned int envc = 0;

#ifdef WIN32
    HANDLE mutex;
#endif

    err = ap_check_cmd_context(cmd, NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE);
    if (err)
    {
        return err;
    }

    if (*fs_path == '\0')
        return "AppClass requires a pathname!?";

    if ((err = fcgienc_config_set_fcgienc_uid_n_gid(1)) != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);

#ifdef APACHE2
    if (apr_filepath_merge(&fs_path, "", fs_path, 0, p))
        return ap_psprintf(tp, "%s %s: invalid filepath", name, fs_path);
#else
    fs_path = ap_os_canonical_filename(p, fs_path);
#endif
    fs_path = ap_server_root_relative(p, fs_path);

    ap_getparents(fs_path);
    ap_no2slash(fs_path);

    /* See if we've already got one of these configured */
    s = fcgienc_util_fs_get_by_id(fs_path, fcgienc_util_get_server_uid(cmd->server),
                               fcgienc_util_get_server_gid(cmd->server));
    if (s != NULL) {
        if (fcgienc_wrapper) {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined FastCGIENC "
                "server \"%s\" with uid=%ld and gid=%ld",
                name, fs_path, (long) fcgienc_util_get_server_uid(cmd->server),
                (long) fcgienc_util_get_server_gid(cmd->server));
        }
        else {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined FastCGIENC server \"%s\"",
                name, fs_path);
        }
    }

    err = fcgienc_util_fs_is_path_ok(tp, fs_path, NULL);
    if (err != NULL) {
        return ap_psprintf(tp, "%s: \"%s\" %s", name, fs_path, err);
    }

    s = fcgienc_util_fs_new(p);
    s->fs_path = fs_path;
    s->directive = APP_CLASS_STANDARD;
    s->restartOnExit = TRUE;
    s->numProcesses = 1;

#ifdef WIN32

    /* TCP FastCGIENC applications require SystemRoot be present in the environment
     * Put it in both for consistency to the application */
    fcgienc_config_set_env_var(p, envp, &envc, "SystemRoot");

    mutex = CreateMutex(NULL, FALSE, fs_path);
    
    if (mutex == NULL)
    {
        ap_log_error(FCGIENC_LOG_ALERT, fcgienc_apache_main_server,
            "FastCGIENC: CreateMutex() failed");
        return "failed to create FastCGIENC application accept mutex";
    }
    
    SetHandleInformation(mutex, HANDLE_FLAG_INHERIT, TRUE);

    s->mutex_env_string = ap_psprintf(p, "_FCGIENC_MUTEX_=%ld", mutex);

#endif

    /*  Parse directive arguments */
    while (*arg) {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-processes") == 0) {
            if ((err = get_u_int(tp, &arg, &s->numProcesses, 1)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-restart-delay") == 0) {
            if ((err = get_u_int(tp, &arg, &s->restartDelay, 0)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-init-start-delay") == 0) {
            if ((err = get_int(tp, &arg, &s->initStartDelay, 0)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-min-server-life") == 0) {
            if ((err = get_u_int(tp, &arg, &s->minServerLife, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-priority") == 0) {
            if ((err = get_u_int(tp, &arg, &s->processPriority, 0)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-listen-queue-depth") == 0) {
            if ((err = get_u_int(tp, &arg, &s->listenQueueDepth, 1)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            if ((err = get_u_int(tp, &arg, &s->appConnectTimeout, 0)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-idle-timeout") == 0) {
            if ((err = get_u_int(tp, &arg, &s->idle_timeout, 1)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-port") == 0) {
            if ((err = get_u_short(tp, &arg, &s->port, 1)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-socket") == 0) {
            s->socket_path = ap_getword_conf(tp, &arg);
            if (*s->socket_path == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
        }
        else if (strcasecmp(option, "-initial-env") == 0) {
            if ((err = get_env_var(p, &arg, envp, &envc)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-pass-header") == 0) {
            if ((err = get_pass_header(p, &arg, &s->pass_headers)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-flush") == 0) {
            s->flush = 1;
        }
        else if (strcasecmp(option, "-nph") == 0) {
            s->nph = 1;
        }
        else if (strcasecmp(option, "-user") == 0) {
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -user option isn't supported on WIN", name, fs_path);
#else
            s->user = ap_getword_conf(tp, &arg);
            if (*s->user == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else if (strcasecmp(option, "-group") == 0) {
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -group option isn't supported on WIN", name, fs_path);
#else
            s->group = ap_getword_conf(tp, &arg);
            if (*s->group == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else {
            return ap_psprintf(tp, "%s %s: invalid option: %s", name, fs_path, option);
        }
    } /* while */

#ifndef WIN32
    if (fcgienc_wrapper)
    {
        if (s->group == NULL)
        {
            s->group = ap_psprintf(tp, "#%ld", (long)fcgienc_util_get_server_gid(cmd->server));
        }

        if (s->user == NULL)
        {
            s->user = ap_psprintf(p, "#%ld", (long)fcgienc_util_get_server_uid(cmd->server)); 
        }

        s->uid = ap_uname2id(s->user);
        s->gid = ap_gname2id(s->group);
    }
    else if (s->user || s->group)
    {
        ap_log_error(FCGIENC_LOG_WARN, cmd->server, "FastCGIENC: there is no "
                     "encrypt wrapper set, user/group options are ignored");
    }

    if ((err = fcgienc_util_fs_set_uid_n_gid(p, s, s->uid, s->gid)))
    {
        return ap_psprintf(tp, 
            "%s %s: invalid user or group: %s", name, fs_path, err);
    }
#endif /* !WIN32 */

    if (s->socket_path != NULL && s->port != 0) {
        return ap_psprintf(tp,
                "%s %s: -port and -socket are mutually exclusive options",
                name, fs_path);
    }

    /* Move env array to a surviving pool */
    s->envp = (char **)ap_pcalloc(p, sizeof(char *) * (envc + 4));
    memcpy(s->envp, envp, sizeof(char *) * envc);

    /* Initialize process structs */
    s->procs = fcgienc_util_fs_create_procs(p, s->numProcesses);

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = fcgienc_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
                                &s->socket_addr_len, NULL, s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
#ifdef WIN32
        err = fcgienc_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->dest_addr,
                                          &s->socket_addr_len, "localhost", s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
#endif
    } else {
        if (s->socket_path == NULL)
             s->socket_path = fcgienc_util_socket_hash_filename(tp, fs_path, s->user, s->group);

        if (fcgienc_socket_dir == NULL)
        {
#ifdef WIN32
            fcgienc_socket_dir = DEFAULT_SOCK_DIR;
#else
            fcgienc_socket_dir = ap_server_root_relative(p, DEFAULT_SOCK_DIR);
#endif
        }

        s->socket_path = fcgienc_util_socket_make_path_absolute(p, s->socket_path, 0);
#ifndef WIN32
        err = fcgienc_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
#endif
    }

    /* Add it to the list of FastCGIENC servers */
    fcgienc_util_fs_add(s);

    return NULL;
}

/*******************************************************************************
 * Configure a static FastCGIENC server that is started/managed elsewhere.
 */
const char *fcgienc_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg)
{
    fcgienc_server *s;
    pool * const p = cmd->pool, *tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    char *fs_path = ap_getword_conf(p, &arg);
    const char *option, *err;

    err = ap_check_cmd_context(cmd, NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE);
    if (err) {
        return err;
    }

    if (!*fs_path) {
        return ap_pstrcat(tp, name, " requires a path and either a -socket or -host option", NULL);
    }

#ifdef APACHE2
    if (apr_filepath_merge(&fs_path, "", fs_path, 0, p))
        return ap_psprintf(tp, "%s %s: invalid filepath", name, fs_path);
#else
    fs_path = ap_os_canonical_filename(p, fs_path);
#endif

    fs_path = ap_server_root_relative(p, fs_path);

    ap_getparents(fs_path);
    ap_no2slash(fs_path);

    /* See if we've already got one of these bettys configured */
    s = fcgienc_util_fs_get_by_id(fs_path, fcgienc_util_get_server_uid(cmd->server),
                               fcgienc_util_get_server_gid(cmd->server));
    if (s != NULL) {
        if (fcgienc_wrapper) {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined class \"%s\" "
                "with uid=%ld and gid=%ld",
                name, fs_path, (long) fcgienc_util_get_server_uid(cmd->server),
                (long) fcgienc_util_get_server_gid(cmd->server));
        }
        else 
        {
            return ap_psprintf(tp,
                "%s: redefinition of previously defined class \"%s\"", name, fs_path);
        }
    }

    s = fcgienc_util_fs_new(p);
    s->fs_path = fs_path;
    s->directive = APP_CLASS_EXTERNAL;

    /*  Parse directive arguments */
    while (*arg != '\0') {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-host") == 0) {
            if ((err = get_host_n_port(p, &arg, &s->host, &s->port)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-socket") == 0) {
            s->socket_path = ap_getword_conf(tp, &arg);
            if (*s->socket_path == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            if ((err = get_u_int(tp, &arg, &s->appConnectTimeout, 0)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-idle-timeout") == 0) {
            if ((err = get_u_int(tp, &arg, &s->idle_timeout, 1)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-nph") == 0) {
            s->nph = 1;
        }
        else if (strcasecmp(option, "-pass-header") == 0) {
            if ((err = get_pass_header(p, &arg, &s->pass_headers)))
                return invalid_value(tp, name, fs_path, option, err);
        }
        else if (strcasecmp(option, "-flush") == 0) {
            s->flush = 1;
        }
        else if (strcasecmp(option, "-user") == 0) {
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -user option isn't supported on WIN", name, fs_path);
#else
            s->user = ap_getword_conf(tp, &arg);
            if (*s->user == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else if (strcasecmp(option, "-group") == 0) {
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -group option isn't supported on WIN", name, fs_path);
#else
            s->group = ap_getword_conf(tp, &arg);
            if (*s->group == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else {
            return ap_psprintf(tp, "%s %s: invalid option: %s", name, fs_path, option);
        }
    } /* while */


#ifndef WIN32
    if (fcgienc_wrapper)
    {
        if (s->group == NULL)
        {
            s->group = ap_psprintf(tp, "#%ld", (long)fcgienc_util_get_server_gid(cmd->server));
        }

        if (s->user == NULL)
        {
            s->user = ap_psprintf(p, "#%ld", (long)fcgienc_util_get_server_uid(cmd->server));
        }

        s->uid = ap_uname2id(s->user);
        s->gid = ap_gname2id(s->group);
    }
    else if (s->user || s->group)
    {
        ap_log_error(FCGIENC_LOG_WARN, cmd->server, "FastCGIENC: there is no "
                     "encrypt wrapper set, user/group options are ignored");
    }

    if ((err = fcgienc_util_fs_set_uid_n_gid(p, s, s->uid, s->gid)))
    {
        return ap_psprintf(tp,
            "%s %s: invalid user or group: %s", name, fs_path, err);
    }
#endif /* !WIN32 */

    /* Require one of -socket or -host, but not both */
    if (s->socket_path != NULL && s->port != 0) {
        return ap_psprintf(tp,
            "%s %s: -host and -socket are mutually exclusive options",
            name, fs_path);
    }
    if (s->socket_path == NULL && s->port == 0) {
        return ap_psprintf(tp,
            "%s %s: -socket or -host option missing", name, fs_path);
    }

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = fcgienc_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
            &s->socket_addr_len, s->host, s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    } else {

        if (fcgienc_socket_dir == NULL)
        {
#ifdef WIN32
            fcgienc_socket_dir = DEFAULT_SOCK_DIR;
#else
            fcgienc_socket_dir = ap_server_root_relative(p, DEFAULT_SOCK_DIR);
#endif
        }

        s->socket_path = fcgienc_util_socket_make_path_absolute(p, s->socket_path, 0);
#ifndef WIN32
        err = fcgienc_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
#endif
    }

    /* Add it to the list of FastCGIENC servers */
    fcgienc_util_fs_add(s);

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * fcgienc_config_set_config --
 *
 *      Implements the FastCGIENC FCGIConfig configuration directive.
 *      This command adds routines to control the execution of the
 *      dynamic FastCGIENC processes.
 *
 *
 *----------------------------------------------------------------------
 */
const char *fcgienc_config_set_config(cmd_parms *cmd, void *dummy, const char *arg)
{
    pool * const p = cmd->pool;
    pool * const tp = cmd->temp_pool;
    const char *err, *option;
    const char * const name = cmd->cmd->name;

    /* Allocate temp storage for an initial environment */
    unsigned int envc = 0;
    char **envp = (char **)ap_pcalloc(tp, sizeof(char *) * (MAX_INIT_ENV_VARS + 3));

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    /* Parse the directive arguments */
    while (*arg) {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-maxProcesses") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicMaxProcs, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-minProcesses") == 0) {
            if ((err = get_int(tp, &arg, &dynamicMinProcs, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-maxClassProcesses") == 0) {
            if ((err = get_int(tp, &arg, &dynamicMaxClassProcs, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-killInterval") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicKillInterval, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-updateInterval") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicUpdateInterval, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-gainValue") == 0) {
            if ((err = get_float(tp, &arg, &dynamicGain, 0.0, 1.0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if ((strcasecmp(option, "-singleThreshold") == 0)
		    || (strcasecmp(option, "-singleThreshhold") == 0)) 
        {
            if ((err = get_int(tp, &arg, &dynamicThreshold1, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if ((strcasecmp(option, "-multiThreshold") == 0)
		    || (strcasecmp(option, "-multiThreshhold") == 0)) 
        {
            if ((err = get_int(tp, &arg, &dynamicThresholdN, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-startDelay") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicPleaseStartDelay, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-initial-env") == 0) {
            if ((err = get_env_var(p, &arg, envp, &envc)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-pass-header") == 0) {
            if ((err = get_pass_header(p, &arg, &dynamic_pass_headers)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicAppConnectTimeout, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-idle-timeout") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamic_idle_timeout, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-listen-queue-depth") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicListenQueueDepth, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-min-server-life") == 0) {
            if ((err = get_int(tp, &arg, &dynamicMinServerLife, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-restart-delay") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicRestartDelay, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-init-start-delay") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicInitStartDelay, 0)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-processSlack") == 0) {
            if ((err = get_u_int(tp, &arg, &dynamicProcessSlack, 1)))
                return invalid_value(tp, name, NULL, option, err);
        }
        else if (strcasecmp(option, "-restart") == 0) {
            dynamicAutoRestart = 1;
        }
        else if (strcasecmp(option, "-autoUpdate") == 0) {
            dynamicAutoUpdate = 1;
		}
        else if (strcasecmp(option, "-flush") == 0) {
            dynamicFlush = TRUE;
        }
        else {
            return ap_psprintf(tp, "%s: invalid option: %s", name, option);
        }
    } /* while */

    if (dynamicProcessSlack >= dynamicMaxProcs + 1) {
	    /* the kill policy would work unexpectedly */
    	return ap_psprintf(tp, 
            "%s: processSlack (%u) must be less than maxProcesses (%u) + 1", 
        	name, dynamicProcessSlack, dynamicMaxProcs);
    }

    /* Move env array to a surviving pool, leave 2 extra slots for 
     * WIN32 _FCGIENC_MUTEX_ and _FCGIENC_SHUTDOWN_EVENT_ */
    dynamicEnvp = (char **)ap_pcalloc(p, sizeof(char *) * (envc + 4));
    memcpy(dynamicEnvp, envp, sizeof(char *) * envc);

    return NULL;
}

void *fcgienc_config_create_dir_config(pool *p, char *dummy)
{
    fcgienc_dir_config *dir_config = ap_pcalloc(p, sizeof(fcgienc_dir_config));

    dir_config->authenticator_options = FCGIENC_AUTHORITATIVE;
    dir_config->authorizer_options = FCGIENC_AUTHORITATIVE;
    dir_config->access_checker_options = FCGIENC_AUTHORITATIVE;

    return dir_config;
}


const char *fcgienc_config_new_auth_server(cmd_parms * cmd,
    void * dircfg, const char *fs_path, const char * compat)
{
    fcgienc_dir_config * dir_config = (fcgienc_dir_config *) dircfg;
    pool * const tp = cmd->temp_pool;
    char * auth_server;

#ifdef APACHE2
    if (apr_filepath_merge(&auth_server, "", fs_path, 0, cmd->pool))
        return ap_psprintf(tp, "%s %s: invalid filepath", cmd->cmd->name, fs_path);
#else
    auth_server = (char *) ap_os_canonical_filename(cmd->pool, fs_path);
#endif

    auth_server = ap_server_root_relative(cmd->pool, auth_server);

    /* Make sure its already configured or at least a candidate for dynamic */
    if (fcgienc_util_fs_get_by_id(auth_server, fcgienc_util_get_server_uid(cmd->server),
                               fcgienc_util_get_server_gid(cmd->server)) == NULL) 
    {
        const char *err = fcgienc_util_fs_is_path_ok(tp, auth_server, NULL);
        if (err)
            return ap_psprintf(tp, "%s: \"%s\" %s", cmd->cmd->name, auth_server, err);
    }

    if (compat && strcasecmp(compat, "-compat"))
        return ap_psprintf(cmd->temp_pool, "%s: unknown option: \"%s\"", cmd->cmd->name, compat);

    switch((int)cmd->info) {
        case FCGIENC_AUTH_TYPE_AUTHENTICATOR:
            dir_config->authenticator = auth_server;
            dir_config->authenticator_options |= (compat) ? FCGIENC_COMPAT : 0;
            break;
        case FCGIENC_AUTH_TYPE_AUTHORIZER:
            dir_config->authorizer = auth_server;
            dir_config->authorizer_options |= (compat) ? FCGIENC_COMPAT : 0;
            break;
        case FCGIENC_AUTH_TYPE_ACCESS_CHECKER:
            dir_config->access_checker = auth_server;
            dir_config->access_checker_options |= (compat) ? FCGIENC_COMPAT : 0;
            break;
    }

    return NULL;
}

const char *fcgienc_config_set_authoritative_slot(cmd_parms * cmd,
    void * dir_config, int arg)
{
    int offset = (int)(long)cmd->info;

    if (arg)
        *((u_char *)dir_config + offset) |= FCGIENC_AUTHORITATIVE;
    else
        *((u_char *)dir_config + offset) &= ~FCGIENC_AUTHORITATIVE;

    return NULL;
}

/*******************************************************************************
 * Set Sproxyd log path
 */
const char *fcgienc_config_set_logpath(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	if (arg1)
		fcgienc_logpath = ap_getword_conf(cmd->pool, &arg1);

	if (arg2)
	{
		fcgienc_loglevel = atoi(arg2);
		if ((fcgienc_loglevel < ENCRYPT_LOG_EMERG) || (fcgienc_loglevel > ENCRYPT_LOG_DEBUG))
			fcgienc_loglevel = ENCRYPT_LOG_DEBUG;
	}
	
	return NULL;
}

/*******************************************************************************
 * Configure Memcached server.
 */
const char *fcgienc_config_set_memcached(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	if ((err = get_host_n_port(cmd->pool, &arg, (const char **)&fcgienc_memcached_server, &fcgienc_memcached_port)))
		return ap_psprintf(cmd->pool, "the %s directive should be IP(Hostname):Port/On", cmd->cmd->name);

	return NULL;
}

/*******************************************************************************
 * Enable, disable Encrypt feature.
 */
const char *fcgienc_config_set_encrypt(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (strcasecmp(arg, "Off") == 0) {
        fcgienc_encrypt_flag = FALSE;
    }
	else if (strcasecmp(arg, "On") == 0) {
        fcgienc_encrypt_flag = TRUE;
    }
    else {
		return ap_psprintf(cmd->temp_pool, 
			"the %s directive should be only Off/On", cmd->cmd->name);
	}

	return NULL;
}

/*******************************************************************************
 * Enable, disable Decrypt applications.
 */
const char *fcgienc_config_set_decrypt(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (strcasecmp(arg, "Off") == 0) {
        fcgienc_decrypt_flag = FALSE;
    }
	else if (strcasecmp(arg, "On") == 0) {
        fcgienc_decrypt_flag = TRUE;
    }
    else {
		return ap_psprintf(cmd->temp_pool, 
			"the %s directive should be only Off/On", cmd->cmd->name);
	}

	return NULL;
}

/*******************************************************************************
 * Set Sproxyd Authentication Server.
 */
const char *fcgienc_config_set_authserver(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_authserver = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}

/*******************************************************************************
 * Set Sproxyd Master Key Server.
 */
const char *fcgienc_config_set_masterkeyserver(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_masterkeyserver = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}

/*******************************************************************************
 * Set Sproxyd Data Key Server.
 */
const char *fcgienc_config_set_datakeyserver(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_datakeyserver = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}

/*******************************************************************************
 * Set Crypt Key String.
 */
const char *fcgienc_config_set_keystring(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_cryptkeystring = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}

/*******************************************************************************
 * Set Sproxyd User Name.
 */
const char *fcgienc_config_set_username(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_username = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}

/*******************************************************************************
 * Set Sproxyd User Password.
 */
const char *fcgienc_config_set_password(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

	fcgienc_password = ap_getword_conf(cmd->pool, &arg);

	return NULL;
}