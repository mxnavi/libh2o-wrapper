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
#include <signal.h>
#include <string.h>
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
static pthread_once_t ssl_once = PTHREAD_ONCE_INIT;
static int openssl_inited = 0;
static pthread_once_t signal_once = PTHREAD_ONCE_INIT;

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
    pthread_once(&ssl_once, init_ssl_once);
    return openssl_inited > 0;
}

static void __set_signal_handler(int signo, void (*cb)(int signo))
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = cb;
    sigaction(signo, &action, NULL);
}

static void init_signal_once() { __set_signal_handler(SIGPIPE, SIG_IGN); }

void libh2o_signal_init() { pthread_once(&signal_once, init_signal_once); }

void libh2o_show_socket_err(const char *prefix, int fd)
{
    /**
     * NOT functional because already called in h2o library
     * SO_ERROR
     *  Get and **clear** the pending socket error.
     */
    int so_err = 0;
    socklen_t l = sizeof(so_err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &l) != 0) {
        H2O_LOGW("%s:getsockopt(%d) error: %d %s", prefix, fd, errno,
             strerror(errno));
    } else if (so_err != 0) {
        H2O_LOGW("%s:getsockopt(%d) error: %d %s", prefix, fd, so_err,
             strerror(so_err));
    } else {
        /* No error */
    }
}
