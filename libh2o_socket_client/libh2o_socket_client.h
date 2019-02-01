/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_socket_client.h
*   CREATE DATE : 2018-12-11
*   MODULE      : libh2o_socket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        : this is a socket client library based on libh2o-evloop which
*                   can run multi clients in one event loop
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_SOCKET_CLIENT_H__
#define __INCLUDE_LIBH2O_SOCKET_CLIENT_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "libh2o_socket_client_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct libh2o_socket_client_ctx_t;

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
const char *libh2o_socket_client_get_version(void);

/**
 * moudle init, will init all resources for libh2o socket client
 * @param client_init init parameters
 * @return client context for success or else error
 */
struct libh2o_socket_client_ctx_t *
libh2o_socket_client_start(const struct socket_client_init_t *client_init);

/**
 * moudle stop, will stop work thread for libh2o socket client and
 * release all resources
 * @param c socket client context
 * @return
 */
void libh2o_socket_client_stop(struct libh2o_socket_client_ctx_t *c);

/**
 * request a socket connection to server
 * @param c socket client context pointer
 * @param req request info
 * @param user user data ptr, will be stored in client handle
 * @return socket client connection handle for success or else NULL when error
 */
const struct socket_client_handle_t *
libh2o_socket_client_req(struct libh2o_socket_client_ctx_t *c,
                         const struct socket_client_req_t *req, void *user);

/**
 * queue data to event loop for sending
 * @param clih socket client handle
 * @param buf buffer pointer
 * @param len buffer length in bytes
 * @return len for success or else 0 when error
 * @note buf should be allocated from  heap and *MUST* be valid until on_sent
 * callback
 */
size_t libh2o_socket_client_send(const struct socket_client_handle_t *clih,
                                 const void *buf, size_t len);

/**
 * request close a connection
 * @param clih socket client handle
 * @return void
 * @note should be called after connected
 */
void libh2o_socket_client_release(const struct socket_client_handle_t *clih);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_SOCKET_CLIENT_H__ */
