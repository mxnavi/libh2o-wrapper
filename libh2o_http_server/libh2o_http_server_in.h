/********** Copyright(C) 2017 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_http_server_in.h
*   CREATE DATE : 2018-01-09
*   MODULE      : libh2o_http_server
*   AUTHOR      :
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_HTTP_SERVER_IN_H__
#define __INCLUDE_LIBH2O_HTTP_SERVER_IN_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "h2o.h"
#include "h2o/websocket.h"
#include "h2o/http1.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/
#define HTTP_RESPONSE_BODY_IOV_MAX 4
#define HTTP_RESPONSE_HEADER_MAX 4

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct server_context_t;

/**
 * http response header
 */
struct http_response_header_t {
    const h2o_token_t *token;
    h2o_iovec_t value;
};

/**
 * http response body
 */
struct http_response_body_t {
    size_t cnt;
    h2o_iovec_t data[HTTP_RESPONSE_BODY_IOV_MAX];
};

/**
 * http response data, filled by user
 */
struct http_response_t {
    int status;         /* http response code */
    const char *reason; /* reason, if NULL, default is 'OK' */
    struct http_response_header_t header[HTTP_RESPONSE_HEADER_MAX];
    struct http_response_body_t body;
};

/**
 * http request and response data wrapper
 */
struct http_request_t {
    uint32_t serial;             /* serial no */
    h2o_req_t *req;              /* real http request data */
    struct http_response_t resp; /* filled by user */
};

/**
 * web socket connection handle
 */
struct websocket_handle_t {
    uint32_t serial;
};

/**
 * libh2o_http_server http request callback defination
 *
 * @param param parameter from user
 * @param data pointer of http_request_t
 */
typedef void (*http_server_on_http_request)(void * /* param */,
                                            struct http_request_t * /* data */);
typedef void (*http_server_on_http_resp_timeout)(
    void * /* param */, struct http_request_t * /* data */);
typedef void (*http_server_on_finish_http_request)(
    void * /* param */, struct http_request_t * /* data */);

/**
 * websocket connection handle
 */
struct websocket_handle_t;

/**
 * libh2o_http_server websocket callback defination
 *
 * @param param parameter from user
 * @param buf pointer of message and length of data for sent/recv
 * @param len  message length
 * @param clih websocket connection handle
 */
typedef void (*http_server_on_ws_connected)(
    void * /* param */, struct websocket_handle_t * /* clih */);
typedef void (*http_server_on_ws_recv)(void * /* param */, void * /* buf */,
                                       size_t /* len */,
                                       struct websocket_handle_t * /* clih */);
typedef void (*http_server_on_ws_sent)(void * /* param */, void * /* buf */,
                                       size_t /* len */,
                                       struct websocket_handle_t * /* clih */);
typedef void (*http_server_on_ws_closed)(
    void * /* param */, struct websocket_handle_t * /* clih */);

/**
 * user callback interface
 */
struct server_callback_t {
    /**
     * user data pointer
     */
    void *param;

    /**
     * called in evloop thread when client http request comes
     */
    http_server_on_http_request on_http_req;

    /**
     * called in evloop thread when user not queue respone after *resp_timeout*
     */
    http_server_on_http_resp_timeout on_http_resp_timeout;

    /**
     * called in evloop thread when http response data has been sent
     * can be used for free memory for response header or body
     */
    http_server_on_finish_http_request on_finish_http_req;

    /**
     * called in event loop thread when websocket connection established
     **/
    http_server_on_ws_connected on_ws_connected;

    /**
     * called when client websocket message comes
     */
    http_server_on_ws_recv on_ws_recv;
    /**
     * called in evloop thread when websocket message data has been sent
     * can be used for free memory for websocket message data
     */
    http_server_on_ws_sent on_ws_sent;

    /**
     * called in evloop thread when websocket connection closed
     * can be used for removing connection from manager list
     */
    http_server_on_ws_closed on_ws_closed;
};

/**
 * ssl init infos
 */
struct server_ssl_init_t {
    const char *cert_file;
    const char *key_file;
    const char *ciphers;
};

/**
 * server init infos
 */
struct http_server_init_t {
    const char *host;
    const char **port;
    int resp_timeout; /* response timeout in miliseconds, 0: not response
                         timeout */
    int num_threads;
    const char *doc_root;
    struct server_ssl_init_t ssl_init;
    struct server_callback_t cb;
};

/****************************************************************************
*                       Global Variables Prototype Section                  *
*****************************************************************************/

/****************************************************************************
*                       Functions Prototype Section                         *
*****************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_HTTP_SERVER_IN_H__ */
