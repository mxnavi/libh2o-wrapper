/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_websocket_client_in.h
*   CREATE DATE : 2018-12-11
*   MODULE      : libh2o_websocket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/
#ifndef __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_IN_H__
#define __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_IN_H__

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/
#define WEBSOCKET_FRAME_TYPE_TEXT 0x01
#define WEBSOCKET_FRAME_TYPE_BINARY 0x02

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
struct websocket_client_req_t {
    char *url; /* MUST */
    uint8_t
        opcode; /* websocket opc code: 0x01 for text frame, 0x02 for binary
                   frame */
};

/**
 * websocket client handle
 */
struct websocket_client_handle_t {
    uint32_t serial;
};

/**
 * websocket client callback defination
 *
 * @param param parameter from user
 */
typedef void (*websocket_client_on_connected)(
    void * /* param */, struct websocket_client_handle_t * /* clih */);
typedef void (*websocket_client_on_handshaked)(
    void * /* param */, struct websocket_client_handle_t * /* clih */);
typedef void (*websocket_client_on_sent)(
    void * /* param */, void * /* buf */, size_t /* len */,
    struct websocket_client_handle_t * /* clih */);
typedef void (*websocket_client_on_recv)(
    void * /* param */, void * /* buf */, size_t /* len */,
    struct websocket_client_handle_t * /* clih */);
typedef void (*websocket_client_on_closed)(
    void * /* param */, const char * /* err */,
    struct websocket_client_handle_t * /* clih */);

/**
 * user callback interface
 */
struct websocket_client_callback_t {
    /**
     * user data pointer
     */
    void *param;

    /**
     * called in evloop thread when connected
     */
    websocket_client_on_connected on_connected;

    /**
     * called in evloop thread when websocket hand shake complete
     */
    websocket_client_on_handshaked on_handshaked;

    /**
     * called in evloop thread when user data has been sent
     */
    websocket_client_on_sent on_sent;

    /**
     * called in evloop thread when websocket message has been received
     */
    websocket_client_on_recv on_recv;

    /**
     * called in evloop thread when error or closed
     */
    websocket_client_on_closed on_closed;
};

/**
 * ssl init infos
 */
struct websocket_client_ssl_init_t {
    const char *cert_file;
};

/**
 * init infos
 */
struct websocket_client_init_t {
    int io_timeout; /* io timeout in msec */
    struct websocket_client_callback_t cb;
    struct websocket_client_ssl_init_t ssl_init;
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

#endif /* __INCLUDE_LIBH2O_WEBSOCKET_CLIENT_IN_H__ */
