/********** Copyright(C) 2017 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_cmn.c
 *   CREATE DATE : 2019-04-04
 *   MODULE      : libh2o
 *   AUTHOR      :
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

#define LOG_TAG "libh2o"
// #define LOG_NDEBUG 0
/****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <pthread.h>

#include "libh2o_log.h"

/****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/

/****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int openssl_inited = 0;

/****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

/****************************************************************************
 *                       Functions Implement Section                         *
 *****************************************************************************/
static void init_ssl_once()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ++openssl_inited;
}

int libh2o_ssl_init()
{
    pthread_once(&once, init_ssl_once);
    return openssl_inited > 0;
}

void libh2o_show_socket_err(const char *prefix, int fd)
{
    int so_err = 0;
    socklen_t l = sizeof(so_err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &l) != 0) {
        LOGW("%s:getsockopt(%d) error: %s", prefix, fd, strerror(errno));
    } else if (so_err != 0) {
        LOGW("%s:getsockopt(%d) error: %s", prefix, fd, strerror(so_err));
    }
}
