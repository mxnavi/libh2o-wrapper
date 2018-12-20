/********** Copyright(C) 2017 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_http_server.h
*   CREATE DATE : 2018-01-09
*   MODULE      : libh2o_http_server
*   AUTHOR      :
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_HTTP_SERVER_H__
#define __INCLUDE_LIBH2O_HTTP_SERVER_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "libh2o_http_server_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/

/****************************************************************************
*                       Global Variables Prototype Section                  *
*****************************************************************************/

/****************************************************************************
*                       Functions Prototype Section                         *
*****************************************************************************/
/**
 * get libh2o_http_server moudle version string
 * @return libh2o_http_server module version string
 */
const char *libh2o_http_server_get_version(void);

/**
 * libh2o_http_server moudle init, will init all resources for
 * libh2o_http_server
 * @param server_init server init parameters
 * @return server context ptr for success or else NULL
 */
struct server_context_t *
libh2o_http_server_start(const struct http_server_init_t *server_init);

/**
 * libh2o_http_server moudle stop, will stop work thread for libh2o_http_server
 * and
 * release all resources for libh2o_http_server
 * @param  c server context
 * @return void
 */
void libh2o_http_server_stop(struct server_context_t *c);

/**
 * queue response data to event loop for sending
 * @param req request to which the response goes to
 * @return void
 * @note user should fill req->resp data before calling this method
 * user need alloc response header/body buffers from req->req->pool, and will
 * freed when response sent finish by h2o.
 */
void libh2o_http_server_queue_response(struct http_request_t *req);

/**
 * queue websocket message to event loop for sending to the specific client
 * @param clih target client of the websocket message
 * @param buf pointer of message data for sending
 * @param len  message length in bytes
 * @return > 0 when success or else 0
 * @note user need alloc msg buffer from heap, and can be freed in
 * on_finish_ws_msg callback.
 */
size_t
libh2o_http_server_queue_ws_message(const struct websocket_handle_t *clih,
                                    const void *buf, size_t len);

/**
 * queue websocket broadcast message to event loop for sending to all clients
 * @param buf pointer of message data for sending
 * @param len  message length in bytes
 * @return > 0 when success or else 0
 * @note NO callback will be issued for broadcast messages
 */
size_t libh2o_http_server_broadcast_ws_message(struct server_context_t *c,
                                               const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_HTTP_SERVER_H__ */
