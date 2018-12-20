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

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include "h2o.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct http_client_req_t {
    char *url;          /* MUST */
    const char *method; /* const string, if NULL, default is 'GET' */
    h2o_iovec_t body;   /* optional request body */
};

/**
 * http client handle
 */
struct http_client_handle_t {
    uint32_t serial;
};

/**
 * http client callback defination
 *
 * @param param parameter from user
 */
typedef void (*http_client_on_connected)(
    void * /* param */, const struct http_client_handle_t * /* clih */);
typedef void (*http_client_on_head)(
    void * /* param */, int version, int status, h2o_iovec_t msg,
    h2o_header_t *headers, size_t num_headers,
    const struct http_client_handle_t * /* clih */);
typedef void (*http_client_on_body)(
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
    const char *cert_file;
};

/**
 * init infos
 */
struct http_client_init_t {
    uint64_t io_timeout; /* io timeout in msec */
    struct http_client_callback_t cb;
    struct http_client_ssl_init_t ssl_init;
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

#endif /* __INCLUDE_LIBH2O_HTTP_CLIENT_IN_H__ */
