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

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "libh2o_http_client_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
struct libh2o_http_client_ctx_t;

/*****************************************************************************
 *                       Global Variables Prototype Section                  *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/
/**
 * get h2o moudle version string
 * @return module version string
 */
const char *libh2o_http_client_get_version(void);

/**
 * moudle start, will init all resources for libh2o http client
 * @param client_init init parameters
 * @return client context for success or else error
 * @note the caller will be blocked wating event loop thread ready
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
 * @param user user data ptr, will be stored in client handle
 * @return http client request handle for success or else NULL when error
 */
const struct http_client_handle_t *
libh2o_http_client_req(struct libh2o_http_client_ctx_t *c,
                       struct http_client_req_t *req, void *user);

/**
 * send request body which MUST only called in req.fill_request_body callback
 * @param clih http client handle
 * @param reqbuf request buffer
 * @param is_end_stream  end of request body when 1
 * @return 0 when success or else error
 */
int libh2o_http_client_send_request_body(
    const struct http_client_handle_t *clih, h2o_iovec_t *reqbuf,
    int is_end_stream);

#ifdef LIBH2O_UNIT_TEST
int libh2o_http_client_test(int argc, char **argv);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_HTTP_CLIENT_H__ */
