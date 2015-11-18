/*
 * Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#include "fcgienc.h"
#include "fcgienc_protocol.h"
#include "fcgienc_encap.h"
#include "fcgienc_log.h"

#ifdef APACHE2
#include "apr_lib.h"
#endif

#ifdef WIN32
#pragma warning( disable : 4706)
#endif

 /*******************************************************************************
 * Build and queue a FastCGIENC message header.  It is the caller's
 * responsibility to make sure that there's enough space in the buffer, and
 * that the data bytes (specified by 'len') are queued immediately following
 * this header.
 */
static void queue_header(fcgienc_request *fr, unsigned char type, unsigned int len)
{
    FCGIENC_Header header;

    ASSERT(type > 0);
    ASSERT(type <= FCGIENC_MAXTYPE);
    ASSERT(len <= 0xffff);
    ASSERT(BufferFree(fr->serverOutputBuffer) >= sizeof(FCGIENC_Header));

    /* Assemble and queue the packet header. */
    header.version = FCGIENC_VERSION;
    header.type = type;
    header.requestIdB1 = (unsigned char) (fr->requestId >> 8);
    header.requestIdB0 = (unsigned char) fr->requestId;
    header.contentLengthB1 = (unsigned char) (len / 256);  /* MSB */
    header.contentLengthB0 = (unsigned char) (len % 256);  /* LSB */
    header.paddingLength = 0;
    header.reserved = 0;
    fcgienc_buf_add_block(fr->serverOutputBuffer, (char *) &header, sizeof(FCGIENC_Header));
}

/*******************************************************************************
 * Build a FCGIENC_BeginRequest message body.
 */
static void build_begin_request(unsigned int role, unsigned char keepConnection,
        FCGIENC_BeginRequestBody *body)
{
    ASSERT((role >> 16) == 0);
    body->roleB1 = (unsigned char) (role >>  8);
    body->roleB0 = (unsigned char) role;
    body->flags = (unsigned char) ((keepConnection) ? FCGIENC_KEEP_CONN : 0);
    memset(body->reserved, 0, sizeof(body->reserved));
}

/*******************************************************************************
 * Build and queue a FastCGIENC "Begin Request" message.
 */
void fcgienc_protocol_queue_begin_request(fcgienc_request *fr)
{
    FCGIENC_BeginRequestBody body;
    int bodySize = sizeof(FCGIENC_BeginRequestBody);

    /* We should be the first ones to use this buffer */
    ASSERT(BufferLength(fr->serverOutputBuffer) == 0);

    build_begin_request(fr->role, FALSE, &body);
    queue_header(fr, FCGIENC_BEGIN_REQUEST, bodySize);
    fcgienc_buf_add_block(fr->serverOutputBuffer, (char *) &body, bodySize);
}

/*******************************************************************************
 * Build a FastCGIENC name-value pair (env) header.
 */
static void build_env_header(int nameLen, int valueLen,
        unsigned char *headerBuffPtr, int *headerLenPtr)
{
    unsigned char *startHeaderBuffPtr = headerBuffPtr;

    ASSERT(nameLen >= 0);

    if (nameLen < 0x80) {
        *headerBuffPtr++ = (unsigned char) nameLen;
    } else {
        *headerBuffPtr++ = (unsigned char) ((nameLen >> 24) | 0x80);
        *headerBuffPtr++ = (unsigned char) (nameLen >> 16);
        *headerBuffPtr++ = (unsigned char) (nameLen >> 8);
        *headerBuffPtr++ = (unsigned char) nameLen;
    }

    ASSERT(valueLen >= 0);

    if (valueLen < 0x80) {
        *headerBuffPtr++ = (unsigned char) valueLen;
    } else {
        *headerBuffPtr++ = (unsigned char) ((valueLen >> 24) | 0x80);
        *headerBuffPtr++ = (unsigned char) (valueLen >> 16);
        *headerBuffPtr++ = (unsigned char) (valueLen >> 8);
        *headerBuffPtr++ = (unsigned char) valueLen;
    }
    *headerLenPtr = headerBuffPtr - startHeaderBuffPtr;
}

/* A static fn stolen from Apache's util_script.c...
 * Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *apache_original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL)
        return (char *) ap_pcalloc(r->pool, 1);

    first = r->the_request;	/* use the request-line */

    while (*first && !ap_isspace(*first))
        ++first;		    /* skip over the method */

    while (ap_isspace(*first))
        ++first;		    /* and the space(s) */

    last = first;
    while (*last && !ap_isspace(*last))
        ++last;			    /* end at next whitespace */

    return ap_pstrndup(r->pool, first, last - first);
}

/* Based on Apache's ap_add_cgi_vars() in util_script.c.
 * Apache's spins in sub_req_lookup_uri() trying to setup PATH_TRANSLATED,
 * so we just don't do that part.
 */
static void add_auth_cgi_vars(request_rec *r, const int compat)
{
    table *e = r->subprocess_env;

    ap_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
    ap_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    ap_table_setn(e, "REQUEST_METHOD", r->method);
    ap_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
    ap_table_setn(e, "REQUEST_URI", apache_original_uri(r));

    /* The FastCGIENC spec precludes sending of CONTENT_LENGTH, PATH_INFO,
     * PATH_TRANSLATED, and SCRIPT_NAME (for some reason?).  PATH_TRANSLATED we
     * don't have, its the variable that causes Apache to break trying to set
     * up (and thus the reason this fn exists vs. using ap_add_cgi_vars()). */
    if (compat) {
        ap_table_unset(e, "CONTENT_LENGTH");
        return;
    }

    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh. */
    if (!strcmp(r->protocol, "INCLUDED")) {
        ap_table_setn(e, "SCRIPT_NAME", r->uri);
        if (r->path_info && *r->path_info)
            ap_table_setn(e, "PATH_INFO", r->path_info);
    }
    else if (!r->path_info || !*r->path_info)
        ap_table_setn(e, "SCRIPT_NAME", r->uri);
    else {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);

        ap_table_setn(e, "SCRIPT_NAME", ap_pstrndup(r->pool, r->uri, path_info_start));
        ap_table_setn(e, "PATH_INFO", r->path_info);
    }
}

static void add_pass_header_vars(fcgienc_request *fr)
{
    const array_header *ph = fr->dynamic ? dynamic_pass_headers : fr->fs->pass_headers;

    if (ph) {
        const char **elt = (const char **)ph->elts;
        int i = ph->nelts;

        for ( ; i; --i, ++elt) {
            const char *val = ap_table_get(fr->r->headers_in, *elt);
            if (val) {
                ap_table_setn(fr->r->subprocess_env, *elt, val);
            }
        }
    }
}

/*******************************************************************************
 * Build and queue the environment name-value pairs.  Returns TRUE if the
 * complete ENV was buffered, FALSE otherwise.  Note: envp is updated to
 * reflect the current position in the ENV.
 */
int fcgienc_protocol_queue_env(request_rec *r, fcgienc_request *fr, env_status *env)
{
    int charCount;
	char *usermdStr = NULL;
	int usermdLen = 0;

    if (env->envp == NULL) {
        ap_add_common_vars(r);
        add_pass_header_vars(fr);

        if (fr->role == FCGIENC_RESPONDER)
	        ap_add_cgi_vars(r);
        else
            add_auth_cgi_vars(r, fr->auth_compat);

        env->envp = ap_create_environment(r->pool, r->subprocess_env);
        env->pass = PREP;
    }

    while (*env->envp) {
        switch (env->pass) 
        {
        case PREP:
            env->equalPtr = strchr(*env->envp, '=');
            ASSERT(env->equalPtr != NULL);
            env->nameLen = env->equalPtr - *env->envp;
            env->valueLen = strlen(++env->equalPtr);
            build_env_header(env->nameLen, env->valueLen, env->headerBuff, &env->headerLen);
            env->totalLen = env->headerLen + env->nameLen + env->valueLen;
            env->pass = HEADER;
            /* drop through */

			// drop if "X-SCAL-USERMD"
			if ((fcgienc_encrypt_flag == TRUE) && 
				(strncasecmp(*env->envp, "HTTP_X_SCAL_USERMD", env->nameLen) == 0))
			{
				usermdLen = env->valueLen;
				usermdStr = env->equalPtr;
				env->pass = PREP;
				break;
			}

        case HEADER:
            if (BufferFree(fr->serverOutputBuffer) < (int)(sizeof(FCGIENC_Header) + env->headerLen)) {
                return (FALSE);
            }
            queue_header(fr, FCGIENC_PARAMS, env->totalLen);
            fcgienc_buf_add_block(fr->serverOutputBuffer, (char *)env->headerBuff, env->headerLen);
            env->pass = NAME;
            /* drop through */

        case NAME:
            charCount = fcgienc_buf_add_block(fr->serverOutputBuffer, *env->envp, env->nameLen);
            if (charCount != env->nameLen) {
                *env->envp += charCount;
                env->nameLen -= charCount;
                return (FALSE);
            }
            env->pass = VALUE;
            /* drop through */

        case VALUE:
            charCount = fcgienc_buf_add_block(fr->serverOutputBuffer, env->equalPtr, env->valueLen);
            if (charCount != env->valueLen) {
                env->equalPtr += charCount;
                env->valueLen -= charCount;
                return (FALSE);
            }
            env->pass = PREP;
        }
        ++env->envp;
    }

	if (fcgienc_encrypt_flag == TRUE)
	{
		char *encapbuff;
		int encaplen;
		int mkidlen, dkidlen;
		char headerbuff[8];
		int headerlen, totallen;

		mkidlen = strlen(fr->encryptor.masterKeyId);
		dkidlen = strlen(fr->encryptor.dataKeyId);

		encaplen = (46 + usermdLen + mkidlen + dkidlen) * 2;

		encapbuff = malloc(encaplen);
		if (!encapbuff)
			return FALSE;

		encaplen = encap_metadata(encapbuff, encaplen, \
			fr->encryptor.masterKeyId, mkidlen, \
			fr->encryptor.dataKeyId, dkidlen, \
			usermdStr, usermdLen);

		if (encaplen < 0)
		{
			free(encapbuff);
			return FALSE;
		}

		build_env_header(18, encaplen, (unsigned char*)headerbuff, &headerlen);

		totallen = headerlen + 18 + encaplen;
		if (BufferFree(fr->serverOutputBuffer) < (int)(sizeof(FCGIENC_Header) + headerlen)) {
			return FALSE;
		}
		queue_header(fr, FCGIENC_PARAMS, totallen);
		fcgienc_buf_add_block(fr->serverOutputBuffer, headerbuff, headerlen);

		charCount = fcgienc_buf_add_block(fr->serverOutputBuffer, "HTTP_X_SCAL_USERMD", 18);
		if (charCount != 18) {
			free(encapbuff);
			return FALSE;
		}

		charCount = fcgienc_buf_add_block(fr->serverOutputBuffer, encapbuff, encaplen);

		log_message(ENCRYPT_LOG_DEBUG, "sending X-Scal-Usermd : %s", encapbuff);

		free(encapbuff);

		if (charCount != encaplen) {
			return FALSE;
		}
	}

    if (BufferFree(fr->serverOutputBuffer) < sizeof(FCGIENC_Header)) {
        return(FALSE);
    }
    queue_header(fr, FCGIENC_PARAMS, 0);
    return(TRUE);
}

/*******************************************************************************
 * Queue data from the client input buffer to the FastCGIENC server output
 * buffer (encapsulating the data in FastCGIENC protocol messages).
 */
void fcgienc_protocol_queue_client_buffer(fcgienc_request *fr)
{
    int movelen;
    int in_len, out_free;

    if (fr->eofSent)
        return;

    /*
     * If there's some client data and room for at least one byte
     * of data in the output buffer (after protocol overhead), then
     * move some data to the output buffer.
     */
    in_len = BufferLength(fr->clientInputBuffer);
    out_free = max(0, BufferFree(fr->serverOutputBuffer) - sizeof(FCGIENC_Header));
    movelen = min(in_len, out_free);
    if (movelen > 0) {
        queue_header(fr, FCGIENC_STDIN, movelen);
        fcgienc_buf_get_to_buf(fr->serverOutputBuffer, fr->clientInputBuffer, movelen);
    }

    /*
     * If all the client data has been sent, and there's room
     * in the output buffer, indicate EOF.
     */
    if (movelen == in_len && fr->expectingClientContent <= 0
            && BufferFree(fr->serverOutputBuffer) >= sizeof(FCGIENC_Header))
    {
        queue_header(fr, FCGIENC_STDIN, 0);
        fr->eofSent = TRUE;
    }
}

/*******************************************************************************
 * Read FastCGIENC protocol messages from the FastCGIENC server input buffer into
 * fr->header when parsing headers, to fr->fs_stderr when reading stderr data,
 * or to the client output buffer otherwises.
 */
int fcgienc_protocol_dequeue(pool *p, fcgienc_request *fr)
{
    FCGIENC_Header header;
    int len;

    while (BufferLength(fr->serverInputBuffer) > 0) {
        /*
         * State #1:  looking for the next complete packet header.
         */
        if (fr->gotHeader == FALSE) {
            if (BufferLength(fr->serverInputBuffer) < sizeof(FCGIENC_Header)) {
                return OK;
            }
            fcgienc_buf_get_to_block(fr->serverInputBuffer, (char *) &header,
                    sizeof(FCGIENC_Header));
            /*
             * XXX: Better handling of packets with other version numbers
             * and other packet problems.
             */
            if (header.version != FCGIENC_VERSION) {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
                    "FastCGIENC: comm with server \"%s\" aborted: protocol error: invalid version: %d != FCGIENC_VERSION(%d)",
                    fr->fs_path, header.version, FCGIENC_VERSION);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            if (header.type > FCGIENC_MAXTYPE) {
                ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
                    "FastCGIENC: comm with server \"%s\" aborted: protocol error: invalid type: %d > FCGIENC_MAXTYPE(%d)",
                    fr->fs_path, header.type, FCGIENC_MAXTYPE);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            fr->packetType = header.type;
            fr->dataLen = (header.contentLengthB1 << 8)
                    + header.contentLengthB0;
            fr->gotHeader = TRUE;
            fr->paddingLen = header.paddingLength;
        }

        /*
         * State #2:  got a header, and processing packet bytes.
         */
        len = min(fr->dataLen, BufferLength(fr->serverInputBuffer));
        ASSERT(len >= 0);
        switch (fr->packetType) {
            case FCGIENC_STDOUT:
                if (len > 0) {
                    switch(fr->parseHeader) {
                        case SCAN_CGI_READING_HEADERS:
                            fcgienc_buf_get_to_array(fr->serverInputBuffer, fr->header, len);
                            break;
                        case SCAN_CGI_FINISHED:
                            len = min(BufferFree(fr->clientOutputBuffer), len);
                            if (len > 0) {
                                fcgienc_buf_get_to_buf(fr->clientOutputBuffer, fr->serverInputBuffer, len);
                            } else {
                                return OK;
                            }
                            break;
                        default:
                            /* Toss data on the floor */
                            fcgienc_buf_removed(fr->serverInputBuffer, len);
                            break;
                    }
                    fr->dataLen -= len;
                }
                break;

            case FCGIENC_STDERR:

                if (fr->fs_stderr == NULL)
                {
                    fr->fs_stderr = ap_palloc(p, FCGIENC_SERVER_MAX_STDERR_LINE_LEN + 1);
                }

                /* We're gonna consume all thats here */
                fr->dataLen -= len;

                while (len > 0) 
                {
                    char *null, *end, *start = fr->fs_stderr;

                    /* Get as much as will fit in the buffer */
                    int get_len = min(len, FCGIENC_SERVER_MAX_STDERR_LINE_LEN - fr->fs_stderr_len);
                    fcgienc_buf_get_to_block(fr->serverInputBuffer, start + fr->fs_stderr_len, get_len);
                    len -= get_len;
                    fr->fs_stderr_len += get_len;
                    *(start + fr->fs_stderr_len) = '\0';

                    /* Disallow nulls, we could be nicer but this is the motivator */
                    while ((null = memchr(start, '\0', fr->fs_stderr_len)))
                    {
                        int discard = ++null - start;
                        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
                            "FastCGIENC: server \"%s\" sent a null character in the stderr stream!?, "
                            "discarding %d characters of stderr", fr->fs_path, discard);
                        start = null;
                        fr->fs_stderr_len -= discard;
                    } 

                    /* Print as much as possible  */
                    while ((end = strpbrk(start, "\r\n"))) 
                    {
                        if (start != end)
                        {
                            *end = '\0';
                            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r, 
                                "FastCGIENC: server \"%s\" stderr: %s", fr->fs_path, start);
                        }
                        end++;
                        end += strspn(end, "\r\n");
                        fr->fs_stderr_len -= (end - start);
                        start = end;
                    }

                    if (fr->fs_stderr_len) 
                    {
                        if (start != fr->fs_stderr)
                        {
                            /* Move leftovers down */
                            memmove(fr->fs_stderr, start, fr->fs_stderr_len);
                        }
                        else if (fr->fs_stderr_len == FCGIENC_SERVER_MAX_STDERR_LINE_LEN)
                        {
                            /* Full buffer, dump it and complain */
                            ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r, 
                               "FastCGIENC: server \"%s\" stderr: %s", fr->fs_path, fr->fs_stderr);
                            ap_log_rerror(FCGIENC_LOG_WARN_NOERRNO, fr->r,
                                "FastCGIENC: too much stderr received from server \"%s\", "
                                "increase FCGIENC_SERVER_MAX_STDERR_LINE_LEN (%d) and rebuild "
                                "or use \"\\n\" to terminate lines",
                                fr->fs_path, FCGIENC_SERVER_MAX_STDERR_LINE_LEN);
                            fr->fs_stderr_len = 0;
                        }
                    }
                }
                break;

            case FCGIENC_END_REQUEST:
                if (!fr->readingEndRequestBody) {
                    if (fr->dataLen != sizeof(FCGIENC_EndRequestBody)) {
                        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
                            "FastCGIENC: comm with server \"%s\" aborted: protocol error: "
                            "invalid FCGIENC_END_REQUEST size: "
                            "%d != sizeof(FCGIENC_EndRequestBody)(%d)",
                            fr->fs_path, fr->dataLen, sizeof(FCGIENC_EndRequestBody));
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    fr->readingEndRequestBody = TRUE;
                }
                if (len>0) {
                    fcgienc_buf_get_to_buf(fr->erBufPtr, fr->serverInputBuffer, len);
                    fr->dataLen -= len;
                }
                if (fr->dataLen == 0) {
                    FCGIENC_EndRequestBody *erBody = &fr->endRequestBody;
                    fcgienc_buf_get_to_block(
                        fr->erBufPtr, (char *) &fr->endRequestBody,
                        sizeof(FCGIENC_EndRequestBody));
                    if (erBody->protocolStatus != FCGIENC_REQUEST_COMPLETE) {
                        /*
                         * XXX: What to do with FCGIENC_OVERLOADED?
                         */
                        ap_log_rerror(FCGIENC_LOG_ERR_NOERRNO, fr->r,
                            "FastCGIENC: comm with server \"%s\" aborted: protocol error: invalid FCGIENC_END_REQUEST status: "
                            "%d != FCGIENC_REQUEST_COMPLETE(%d)", fr->fs_path,
                            erBody->protocolStatus, FCGIENC_REQUEST_COMPLETE);
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    fr->exitStatus = (erBody->appStatusB3 << 24)
                        + (erBody->appStatusB2 << 16)
                        + (erBody->appStatusB1 <<  8)
                        + (erBody->appStatusB0 );
                    fr->exitStatusSet = TRUE;
                    fr->readingEndRequestBody = FALSE;
                }
                break;
            case FCGIENC_GET_VALUES_RESULT:
                /* XXX coming soon */
            case FCGIENC_UNKNOWN_TYPE:
                /* XXX coming soon */

            /*
             * XXX Ignore unknown packet types from the FastCGIENC server.
             */
            default:
                fcgienc_buf_toss(fr->serverInputBuffer, len);
                fr->dataLen -= len;
                break;
        } /* switch */

        /*
         * Discard padding, then start looking for
         * the next header.
         */
        if (fr->dataLen == 0) {
            if (fr->paddingLen > 0) {
                len = min(fr->paddingLen,
                        BufferLength(fr->serverInputBuffer));
                fcgienc_buf_toss(fr->serverInputBuffer, len);
                fr->paddingLen -= len;
            }
            if (fr->paddingLen == 0) {
                fr->gotHeader = FALSE;
            }
        }
    } /* while */
    return OK;
}
