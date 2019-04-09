/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_socket_server_in.h
 *   CREATE DATE : 2019-04-08
 *   MODULE      : libh2o_socket_server
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_LIBH2O_SOCKET_SERVER_IN_H__
#define __INCLUDE_LIBH2O_SOCKET_SERVER_IN_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/

struct socket_server_req_t {
    const char *host; /* const string pointer from user */
    const char *port; /* const string pointer from user */
};

/**
 * socket server handle
 */
struct socket_server_handle_t {
    uint64_t serial;
    void *user;
};

/**
 * socket server callback defination
 *
 * @param param parameter from user
 */
typedef void (*socket_server_on_listen_error)(
    void * /* param */, const char * /* err */,
    const struct socket_server_req_t * /* req */);
typedef void (*socket_server_on_connected)(
    void * /* param */, const struct socket_server_handle_t * /* clih */);
typedef void (*socket_server_on_data)(
    void * /* param */, void * /* buf */, size_t /* len */,
    const struct socket_server_handle_t * /* clih */);
typedef void (*socket_server_on_sent)(
    void * /* param */, void * /* buf */, size_t /* len */, int /* sent */,
    const struct socket_server_handle_t * /* clih */);
typedef void (*socket_server_on_closed)(
    void * /* param */, const char * /* err */,
    const struct socket_server_handle_t * /* clih */);

/**
 * user callback interface
 */
struct socket_server_callback_t {
    /**
     * user data pointer
     */
    void *param;

    socket_server_on_listen_error on_listen_err;

    /**
     * called in evloop thread when connected
     */
    socket_server_on_connected on_connected;

    /**
     * called in evloop thread when input data ready
     */
    socket_server_on_data on_data;

    /**
     * called in evloop thread when user data has been sent
     */
    socket_server_on_sent on_sent;

    /**
     * called in evloop thread when error or closed
     */
    socket_server_on_closed on_closed;
};

/**
 * ssl init infos
 */
struct socket_server_ssl_init_t {
    const char *cert_file; /* server certificate file */
    const char *key_file;  /* server key file */
    int (*passwd_cb)(char *buf, int size, int rwflag, void *u);
    const char *cipher_list;
};

/**
 * init infos
 */
struct socket_server_init_t {
    int io_timeout; /* io timeout in msec */
    struct socket_server_callback_t cb;
    struct socket_server_ssl_init_t ssl_init;
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

#endif /* __INCLUDE_LIBH2O_SOCKET_SERVER_IN_H__ */
