/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_http_client_in.h
 *   CREATE DATE : 2018-12-11
 *   MODULE      : libh2o_http_client
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_LIBH2O_HTTP_CLIENT_IN_H__
#define __INCLUDE_LIBH2O_HTTP_CLIENT_IN_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include "h2o.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#ifndef HTTP_REQUEST_HEADER_MAX
#define HTTP_REQUEST_HEADER_MAX 4
#endif

#define SHOW_STATUS_LINE(version, status, msg)                                 \
    do {                                                                       \
        char __buf[1024];                                                      \
        int r = 0;                                                             \
        r +=                                                                   \
            snprintf(__buf + r, sizeof(__buf) - r, "HTTP/%d", (version >> 8)); \
        if ((version & 0xff) != 0) {                                           \
            r +=                                                               \
                snprintf(__buf + r, sizeof(__buf) - r, ".%d", version & 0xff); \
        }                                                                      \
        r += snprintf(__buf + r, sizeof(__buf) - r, " %d", status);            \
        if (msg.len != 0) {                                                    \
            r += snprintf(__buf + r, sizeof(__buf) - r, " %.*s\n",             \
                          (int)msg.len, msg.base);                             \
        } else {                                                               \
            r += snprintf(__buf + r, sizeof(__buf) - r, "\n");                 \
        }                                                                      \
        LOGI("%.*s", r, __buf);                                                \
    } while (0)

#define SHOW_RESPONSE_HEADERS(version, status, msg, headers, num_headers)      \
    do {                                                                       \
        SHOW_STATUS_LINE(version, status, msg);                                \
        for (size_t i = 0; i != num_headers; ++i) {                            \
            const char *name = headers[i].orig_name;                           \
            if (name == NULL) name = headers[i].name->base;                    \
            LOGI("%.*s: %.*s\n", (int)headers[i].name->len, name,              \
                 (int)headers[i].value.len, headers[i].value.base);            \
        }                                                                      \
    } while (0)

#define LIBH2O_EVLOOP_TIMER_REPEAT 0x1

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/**
 * optional http request header
 */
struct http_request_header_t {
    const h2o_token_t *token;
    h2o_iovec_t value;
};

struct http_client_handle_t;
struct http_client_req_t {
    char *url;          /* MUST */
    const char *method; /* const string, if NULL, default is 'GET' */
    struct {
        h2o_iovec_t body; /* optional request body */
        /*  NULL or optional fill body by user when body not provided */
        void (*fill_request_body)(
            void * /* param */, const struct http_client_handle_t * /* clih */);
    };
    struct http_request_header_t
        header[HTTP_REQUEST_HEADER_MAX]; /* optional request header */
};

/**
 * http client handle
 */
struct http_client_handle_t {
    uint32_t serial;
    void *user;
};

/**
 * data statistics
 * @note for http client, the request/response header is not considered
 */
struct data_statistics_t {
    size_t bytes_read;    /* total bytes received */
    size_t bytes_written; /* total bytes sent */
};

/**
 * http client callback defination
 *
 * @param param parameter from user
 */
typedef int (*http_client_on_connected)(
    void * /* param */, const struct http_client_handle_t * /* clih */);
typedef int (*http_client_on_head)(
    void * /* param */, int version, int status, h2o_iovec_t msg,
    h2o_header_t *headers, size_t num_headers,
    const struct http_client_handle_t * /* clih */);
typedef int (*http_client_on_body)(
    void * /* param */, void * /* buf */, size_t /* len */, int /* eos */,
    const struct http_client_handle_t * /* clih */);
typedef void (*http_client_on_finish)(
    void * /* param */, const char * /* err */,
    const struct data_statistics_t *,
    const struct http_client_handle_t * /* clih */);

/**
 * user callback interface
 */
struct http_client_callback_t {
    /**
     * user data pointer
     */
    void *param;

    /**
     * called in evloop thread when connected
     */
    http_client_on_connected on_connected;

    /**
     * called in evloop thread when input data ready
     */
    http_client_on_head on_head;

    /**
     * called in evloop thread when user data has been sent
     */
    http_client_on_body on_body;

    /**
     * called in evloop thread when error or closed
     */
    http_client_on_finish on_finish;
};

/**
 * ssl init infos
 */
struct http_client_ssl_init_t {
    const char *cert_file;     /* server certificate file */
    const char *cli_cert_file; /* client certificate file */
    const char *cli_key_file;  /* client key file */
    int (*passwd_cb)(char *buf, int size, int rwflag, void *u);
};

/**
 * init infos
 */
struct http_client_init_t {
    uint64_t timeout; /* timeout in msec */
    struct http_client_callback_t cb;
    struct http_client_ssl_init_t ssl_init;
    uint32_t chunk_size; /* trunk size or 0 for default */
    int8_t http2_ratio;  /* -1 for default or 0 - 100 */
};

struct libh2o_evloop_timer_t; /* timer instance for evloop */

/* timeout for user */
struct libh2o_evloop_timedout_t {
    void (*timedout)(void *param, struct libh2o_evloop_timer_t *);
    void *param;
};

/*****************************************************************************
 *                       Global Variables Prototype Section                  *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_HTTP_CLIENT_IN_H__ */
