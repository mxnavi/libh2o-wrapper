/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_socket_client_in.h
*   CREATE DATE : 2018-12-11
*   MODULE      : libh2o_socket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_SOCKET_CLIENT_IN_H__
#define __INCLUDE_LIBH2O_SOCKET_CLIENT_IN_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/

struct socket_client_req_t {
    const char *host; /* const string pointer from user */
    const char *port; /* const string pointer from user */
};

/**
 * socket client handle
 */
struct socket_client_handle_t {
    uint32_t serial;
};

/**
 * socket client callback defination
 *
 * @param param parameter from user
 */
typedef void (*socket_client_on_host_resolved)(
    void * /* param */, struct addrinfo * /* addr */,
    const struct socket_client_handle_t * /* clih */);
typedef void (*socket_client_on_connected)(
    void * /* param */, const struct socket_client_handle_t * /* clih */);
typedef void (*socket_client_on_data)(
    void * /* param */, void * /* buf */, size_t /* len */,
    const struct socket_client_handle_t * /* clih */);
typedef void (*socket_client_on_sent)(
    void * /* param */, void * /* buf */, size_t /* len */, int /* sent */,
    const struct socket_client_handle_t * /* clih */);
typedef void (*socket_client_on_closed)(
    void * /* param */, const char * /* err */,
    const struct socket_client_handle_t * /* clih */);

/**
 * user callback interface
 */
struct socket_client_callback_t {
    /**
     * user data pointer
     */
    void *param;

    /**
     * called in evloop thread when host resolved, maybe NULL
     */
    socket_client_on_host_resolved on_host_resolved;

    /**
     * called in evloop thread when connected
     */
    socket_client_on_connected on_connected;

    /**
     * called in evloop thread when input data ready
     */
    socket_client_on_data on_data;

    /**
     * called in evloop thread when user data has been sent
     */
    socket_client_on_sent on_sent;

    /**
     * called in evloop thread when error or closed
     */
    socket_client_on_closed on_closed;
};

/**
 * ssl init infos
 */
struct socket_client_ssl_init_t {
    const char *cert_file;
};

/**
 * init infos
 */
struct socket_client_init_t {
    int conn_timeout; /* connect timeout in msec */
    int io_timeout; /* io timeout in msec */
    struct socket_client_callback_t cb;
    struct socket_client_ssl_init_t ssl_init;
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

#endif /* __INCLUDE_LIBH2O_SOCKET_CLIENT_IN_H__ */
