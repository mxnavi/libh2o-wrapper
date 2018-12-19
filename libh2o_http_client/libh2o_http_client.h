/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_http_client.h
*   CREATE DATE : 2018-12-11
*   MODULE      : libh2o_http_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        : this is a http client library based on libh2o-evloop which
*                   run multi clients in one event loop
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_HTTP_CLIENT_H__
#define __INCLUDE_LIBH2O_HTTP_CLIENT_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "libh2o_http_client_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct libh2o_http_client_ctx_t;

/****************************************************************************
*                       Global Variables Prototype Section                  *
*****************************************************************************/

/****************************************************************************
*                       Functions Prototype Section                         *
*****************************************************************************/
/**
 * get h2o moudle version string
 * @return module version string
 */
const char *libh2o_http_client_get_version(void);

/**
 * moudle init, will init all resources for libh2o http client
 * @param client_init init parameters
 * @return client context for success or else error
 */
struct libh2o_http_client_ctx_t *
libh2o_http_client_start(const struct http_client_init_t *client_init);

/**
 * moudle stop, will stop work thread for libh2o http client and
 * release all resources
 * @param c http client context
 * @return
 * @note stoo will be blocked waiting for event loop thread quiting
 */
void libh2o_http_client_stop(struct libh2o_http_client_ctx_t *c);

/**
 * queue data to event loop thread for sending
 * @param c http client context pointer
 * @param req  http request
 * @return http client request handle for success or else NULL when error
 */
struct http_client_handle_t *
libh2o_http_client_req(struct libh2o_http_client_ctx_t *c,
                       struct http_client_req_t *req);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_HTTP_CLIENT_H__ */
