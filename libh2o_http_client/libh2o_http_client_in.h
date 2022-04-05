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
    void * /* param */, void * /* buf */, size_t /* len */,
    const struct http_client_handle_t * /* clih */);
typedef void (*http_client_on_finish)(
    void * /* param */, const char * /* err */,
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
    struct {
        int8_t ratio; /* -1 for default or 0 - 100 */
    } http2;
    struct {
        /**
         * (default: 1472)
         */
        uint16_t max_udp_payload_size;

        /**
         * Maximum size of packets that we are willing to send when
         * path-specific information is unavailable. As a path-specific
         * optimization, quicly acting as a server expands this
         * value to `min(local.tp.max_udp_payload_size,
         * remote.tp.max_udp_payload_size,
         * max_size_of_incoming_datagrams)` when it receives the Transport
         * Parameters from the client.
         * (default: 1280)
         */
        uint16_t initial_egress_max_udp_payload_size;

        /**
         * How frequent the endpoint should induce ACKs from the peer,
         * relative to RTT (or CWND) multiplied by 1024. As an example, 128
         * will request the peer to send one ACK every 1/8 RTT (or CWND). 0
         * disables the use of the delayed-ack extension.
         */
        uint16_t ack_frequency;
        int8_t ratio; /* -1 for default or 0 - 100 */
        uint8_t disallowed_delayed_ack : 1;
        uint32_t max_stream_data;
    } http3;
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
