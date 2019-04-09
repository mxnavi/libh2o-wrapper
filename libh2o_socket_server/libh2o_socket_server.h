/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_socket_server.h
 *   CREATE DATE : 2019-04-08
 *   MODULE      : libh2o_socket_server
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        : this is a socket server library based on libh2o-evloop which
 *                   can run multi servers in one event loop
 *****************************************************************************/
#ifndef __INCLUDE_LIBH2O_SOCKET_SERVER_H__
#define __INCLUDE_LIBH2O_SOCKET_SERVER_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include "libh2o_socket_server_in.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct libh2o_socket_server_ctx_t;

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
const char *libh2o_socket_server_get_version(void);

/**
 * moudle init, will init all resources for libh2o socket server
 * @param server_init init parameters
 * @return server context for success or else error
 */
struct libh2o_socket_server_ctx_t *
libh2o_socket_server_start(const struct socket_server_init_t *server_init);

/**
 * moudle stop, will stop work thread for libh2o socket server and
 * release all resources
 * @param c socket server context
 * @return
 */
void libh2o_socket_server_stop(struct libh2o_socket_server_ctx_t *c);

/**
 * request to start socket server
 * @param c socket server context pointer
 * @param req request info
 * @param user user data ptr, will be stored in server handle
 * @return int 0 when success or lese error
 */
int libh2o_socket_server_req(struct libh2o_socket_server_ctx_t *c,
                             const struct socket_server_req_t *req, void *user);

/**
 * queue data to event loop for sending
 * @param clih socket server handle
 * @param buf buffer pointer
 * @param len buffer length in bytes
 * @return len for success or else 0 when error
 * @note buf should be allocated from  heap and *MUST* be valid until on_sent
 * callback
 */
size_t libh2o_socket_server_send(const struct socket_server_handle_t *clih,
                                 const void *buf, size_t len);

/**
 * request close a connection
 * @param clih socket server handle
 * @return void
 * @note should be called after connected
 */
void libh2o_socket_server_release(const struct socket_server_handle_t *clih);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_LIBH2O_SOCKET_SERVER_H__ */
