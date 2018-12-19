/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_websocket_client.h
*   CREATE DATE : 2018-12-11
*   MODULE      : libh2o_websocket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        : this is a websock client library based on libh2o-evloop which
*                   can run multi clients in one event loop
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_H__
#define __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "libh2o_websocket_client_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct libh2o_websocket_client_ctx_t;

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
const char *libh2o_websocket_client_get_version(void);

/**
 * moudle init, will init all resources for libh2o websocket client
 * @param client_init init parameters
 * @return client context for success or else error
 */
struct libh2o_websocket_client_ctx_t *libh2o_websocket_client_start(const struct websocket_client_init_t *client_init);

/**
 * moudle stop, will stop event loop thread for libh2o websocket client and
 * release all resources
 * @param c websocket client context
 * @return void
 * @note the caller will be blocked waiting for event loop thread quiting
 */
void libh2o_websocket_client_stop(struct libh2o_websocket_client_ctx_t *c);

/**
 * request a websocket connection to server
 * @param c websocket client context pointer
 * @param req request info
 * @return websocket client connection handle for success or else NULL when error
 */
struct websocket_client_handle_t *libh2o_websocket_client_req(struct libh2o_websocket_client_ctx_t *c,
                                                              const struct websocket_client_req_t *req);

/**
 * queue data to event loop for sending
 * @param clih websocket client handle
 * @param buf buffer pointer
 * @param len buffer length in bytes
 * @return len for success or else 0 when error
 * @note buf should be allocated from  heap and *MUST* be valid until on_sent callback
 */
size_t libh2o_websocket_client_send(struct websocket_client_handle_t *clih, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_H__ */

