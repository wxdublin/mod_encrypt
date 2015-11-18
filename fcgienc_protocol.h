/* 
 * Baze Ilijoskki <bazeilijoskki@gmail.com>
 */

#ifndef FCGIENC_PROTOCOL_H
#define FCGIENC_PROTOCOL_H

/*
 * Listening socket file number
 */
#define FCGIENC_LISTENSOCK_FILENO 0

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGIENC_Header;

#define FCGIENC_MAX_LENGTH 0xffff

/*
 * Number of bytes in a FCGIENC_Header.  Future versions of the protocol
 * will not reduce this number.
 */
#define FCGIENC_HEADER_LEN  8

/*
 * Value for version component of FCGIENC_Header
 */
#define FCGIENC_VERSION_1           1

/*
 * Current version of the FastCGIENC protocol
 */
#define FCGIENC_VERSION FCGIENC_VERSION_1

/*
 * Values for type component of FCGIENC_Header
 */
#define FCGIENC_BEGIN_REQUEST       1
#define FCGIENC_ABORT_REQUEST       2
#define FCGIENC_END_REQUEST         3
#define FCGIENC_PARAMS              4
#define FCGIENC_STDIN               5
#define FCGIENC_STDOUT              6
#define FCGIENC_STDERR              7
#define FCGIENC_DATA                8
#define FCGIENC_GET_VALUES          9
#define FCGIENC_GET_VALUES_RESULT  10
#define FCGIENC_UNKNOWN_TYPE       11
#define FCGIENC_MAXTYPE (FCGIENC_UNKNOWN_TYPE)

/*
 * Value for requestId component of FCGIENC_Header
 */
#define FCGIENC_NULL_REQUEST_ID     0


typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGIENC_BeginRequestBody;

typedef struct {
    FCGIENC_Header header;
    FCGIENC_BeginRequestBody body;
} FCGIENC_BeginRequestRecord;

/*
 * Mask for flags component of FCGIENC_BeginRequestBody
 */
#define FCGIENC_KEEP_CONN  1

/*
 * Values for role component of FCGIENC_BeginRequestBody
 */
#define FCGIENC_RESPONDER  1
#define FCGIENC_AUTHORIZER 2
#define FCGIENC_FILTER     3


typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGIENC_EndRequestBody;

typedef struct {
    FCGIENC_Header header;
    FCGIENC_EndRequestBody body;
} FCGIENC_EndRequestRecord;

/*
 * Values for protocolStatus component of FCGIENC_EndRequestBody
 */
#define FCGIENC_REQUEST_COMPLETE 0
#define FCGIENC_CANT_MPX_CONN    1
#define FCGIENC_OVERLOADED       2
#define FCGIENC_UNKNOWN_ROLE     3


/*
 * Variable names for FCGIENC_GET_VALUES / FCGIENC_GET_VALUES_RESULT records
 */
#define FCGIENC_MAX_CONNS  "FCGIENC_MAX_CONNS"
#define FCGIENC_MAX_REQS   "FCGIENC_MAX_REQS"
#define FCGIENC_MPXS_CONNS "FCGIENC_MPXS_CONNS"


typedef struct {
    unsigned char type;    
    unsigned char reserved[7];
} FCGIENC_UnknownTypeBody;

typedef struct {
    FCGIENC_Header header;
    FCGIENC_UnknownTypeBody body;
} FCGIENC_UnknownTypeRecord;

#endif  /* FCGIENC_PROTOCOL_H */

