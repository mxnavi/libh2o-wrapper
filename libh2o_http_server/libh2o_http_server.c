/********** Copyright(C) 2017 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_http_server.c
*   CREATE DATE : 2018-01-09
*   MODULE      : libh2o_http_server
*   AUTHOR      :
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/memcached.h"
#include "h2o/websocket.h"

#include "libh2o_http_server.h"

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/
#define UNIT_TEST 1
#define DEBUG_SERIAL 1

#define USE_HTTPS 0
#define USE_MEMCACHED 0

#define CONNECTION_DISPOSED 0x80000000

#define NOTIFICATION_HTTP_RESP 0
#define NOTIFICATION_WS_DATA 1
#define NOTIFICATION_WS_BROADCAST 2
#define NOTIFICATION_QUIT 0xFFFFFFFF

#define DISPOSE_TIMEOUT_MS 1000

#define LOGV(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#define LOGD(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#define LOGI(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#define LOGW(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#define LOGE(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))

#ifndef ASSERT
#define ASSERT assert
#endif

#undef SO_REUSEPORT

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/

/* forward declarations */
struct server_context_t;

struct thread_param_t {
    int thread_index;
    struct server_context_t *c;
};

/**
 * listener context
 */
struct listener_ctx_t {
    h2o_accept_ctx_t accept_ctx;
    h2o_socket_t *sock;
    struct server_context_t *c;
};

/**
 * listener config, we may need more than one listener
 */
struct listener_config_t {
    int fd;
#if defined(__linux__) && defined(SO_REUSEPORT)
    int *reuseport_fds;
#endif

    struct sockaddr_storage addr;
    socklen_t addrlen;
    h2o_hostconf_t **hosts;
    SSL_CTX *ssl_ctx;
    int proxy_protocol;
};

struct server_context_t {
    struct http_server_init_t server_init; /* server init parameters from user */
    h2o_globalconf_t config;
    int tfo_queues; /* tcp fast open */

    struct listener_config_t **listeners;
    size_t num_listeners;

    uint32_t serial_counter;    /* http_request serial counter */
    uint32_t ws_serial_counter; /* websocket serial counter */
    uint32_t broadcast_serial_counter;

    pthread_key_t tls;

    struct {
        pthread_t tid;
        int exit_loop;
        h2o_context_t ctx;
        h2o_linklist_t conns;             /* http connections */
        h2o_linklist_t ws_conns;          /* websocket connection list */
        h2o_multithread_receiver_t server_notifications;
#if USE_MEMCACHED
        h2o_multithread_receiver_t memcached;
#endif

    } * threads;
    struct {
        int _num_connections; /* number of currently handled incoming connections, should use atomic functions to update the value
                                 */
    } state;

    /**
     * TODO: every listener should have it's own ssl context?
     */
    SSL_CTX *ssl_ctx;
};

struct server_handler_t {
    h2o_handler_t super;
    struct server_context_t *c;
};

/**
 * web socket client handle
 */
struct websocket_handle_t {
    uint32_t serial;
};

/**
 * MUST the first member for sub struct
 */
struct notification_cmn_t {
    h2o_multithread_message_t super; /* used to call h2o_multithread_send_message() */
    struct server_context_t *c;
    uint32_t cmd;
};

struct notification_quit_t {
    struct notification_cmn_t cmn;
};

/**
 * wrapper client request and response data
 */
struct notification_http_conn_t {
    struct notification_cmn_t cmn;
    int thread_index;    /* to which thread this connection belongs to */
    h2o_linklist_t node; /* linked to server context 'conns' */
    struct http_request_t req;
};

/**
 * wrapper websocket connection
 */
struct notification_ws_conn_t {
    struct notification_cmn_t cmn;
    int thread_index;             /* to which thread this connection belongs to */
    h2o_linklist_t pending;       /* list for pending data sent */
    h2o_timer_t dispose_timeout;
    h2o_websocket_conn_t *wsconn; /* real connection */
    uint32_t serial_counter;      /* data serial counter */
    struct websocket_handle_t clih;
};

struct notification_data_t {
    struct notification_cmn_t cmn;
    struct notification_ws_conn_t *conn;
    h2o_iovec_t data;
    uint64_t serial;
};

struct server_tls_data_t {
    int __thread_index;
};

/****************************************************************************
*                       Global Variables Section                            *
*****************************************************************************/
static pthread_mutex_t *mutexes;

/****************************************************************************
*                       Functions Prototype Section                         *
*****************************************************************************/
static void release_notification_ws_conn(struct notification_ws_conn_t *conn);

/****************************************************************************
*                       Functions Implement Section                         *
*****************************************************************************/
static int get_current_thread_index(struct server_context_t *c)
{
    struct server_tls_data_t *p;

    p = pthread_getspecific(c->tls);
    if (H2O_LIKELY(p != NULL)) {
        return p->__thread_index;
    }
    return -1;
}

static void set_current_thread_index(struct server_context_t *c, int thread_index)
{
    struct server_tls_data_t *p;

    p = pthread_getspecific(c->tls);
    if (p == NULL) {
        p = h2o_mem_alloc(sizeof(*p));
        memset(p, 0x00, sizeof(*p));
        p->__thread_index = thread_index;
        pthread_setspecific(c->tls, p);
    }
}

static void server_tls_destroy(void *value)
{
    free(value);
}

static void set_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        LOGE("failed to set FD_CLOEXEC");
    }
}

static void lock_callback(int mode, int n, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(mutexes + n);
    } else if ((mode & CRYPTO_UNLOCK) != 0) {
        pthread_mutex_unlock(mutexes + n);
    } else {
        ASSERT(!"unexpected mode");
    }
}

static unsigned long thread_id_callback(void)
{
    return (unsigned long)pthread_self();
}

static int add_lock_callback(int *num, int amount, int type, const char *file, int line)
{
    (void)type;
    (void)file;
    (void)line;

    return __sync_add_and_fetch(num, amount);
}

static void init_openssl(void)
{
    static int openssl_inited = 0;
    if (openssl_inited == 0) {
        openssl_inited = 1;
        int nlocks = CRYPTO_num_locks(), i;
        mutexes = h2o_mem_alloc(sizeof(*mutexes) * nlocks);
        for (i = 0; i != nlocks; ++i)
            pthread_mutex_init(mutexes + i, NULL);
        CRYPTO_set_locking_callback(lock_callback);
        CRYPTO_set_id_callback(thread_id_callback);
        CRYPTO_set_add_lock_callback(add_lock_callback);

        /* Dynamic locks are only used by the CHIL engine at this time */

        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
    }
}

static void callback_on_http_req(struct notification_http_conn_t *conn)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_http_req) {
        p->cb.on_http_req(p->cb.param, &conn->req);
    }
}

static void callback_on_finish_http_req(struct notification_http_conn_t *conn)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_finish_http_req) {
        p->cb.on_finish_http_req(p->cb.param, &conn->req);
    }
}

static void callback_on_ws_connected(struct notification_ws_conn_t *conn)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_ws_connected) {
        p->cb.on_ws_connected(p->cb.param, &conn->clih);
    }
}

static void callback_on_ws_sent(struct notification_ws_conn_t *conn, void *buf, size_t len, int sent)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_ws_sent) {
        p->cb.on_ws_sent(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_ws_recv(struct notification_ws_conn_t *conn, void *buf, size_t len)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_ws_recv) {
        p->cb.on_ws_recv(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_ws_closed(struct notification_ws_conn_t *conn, const char *err)
{
    struct server_context_t *c = conn->cmn.c;
    struct http_server_init_t *p = &c->server_init;

    if (p->cb.on_ws_closed) {
        p->cb.on_ws_closed(p->cb.param, &conn->clih);
    }
}

static void dispose_timeout_cb(h2o_timer_t *entry)
{
    struct notification_ws_conn_t *conn;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_ws_conn_t, dispose_timeout, entry);
    release_notification_ws_conn(conn);
}

static void on_ws_message(h2o_websocket_conn_t *_conn, const struct wslay_event_on_msg_recv_arg *arg)
{
    struct notification_ws_conn_t *conn = _conn->data;
    struct server_context_t *c = conn->cmn.c;
    int thread_index = conn->thread_index;

    ASSERT(conn->wsconn == _conn);
    ASSERT(thread_index == get_current_thread_index(c));

    if (arg == NULL) {
        callback_on_ws_closed(conn, "NULL");
        h2o_websocket_close(conn->wsconn);
        conn->wsconn = NULL;

        conn->dispose_timeout.cb = dispose_timeout_cb;
        h2o_timer_link(c->threads[thread_index].ctx.loop, DISPOSE_TIMEOUT_MS, &conn->dispose_timeout);
        return;
    }

    if (!wslay_is_ctrl_frame(arg->opcode)) {
        callback_on_ws_recv(conn, (void *)arg->msg, arg->msg_length);
    }
}

static void on_handler_dispose(h2o_handler_t *self)
{
}

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    struct server_handler_t *handler;
    struct server_context_t *c;
    const char *client_key;
    int thread_index;

    handler = H2O_STRUCT_FROM_MEMBER(struct server_handler_t, super, self);
    c = handler->c;

    thread_index = get_current_thread_index(c);

    if (h2o_is_websocket_handshake(req, &client_key) == 0 && client_key != NULL) {
        h2o_websocket_conn_t *wsconn;
        struct notification_ws_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
        memset(conn, 0x00, sizeof(*conn));

        // LOGV("%s() thread_index: %d websocket client_key: %.24s", __FUNCTION__, thread_index, client_key);

        conn->cmn.c = c;
        wsconn = h2o_upgrade_to_websocket(req, client_key, conn, on_ws_message);
        conn->wsconn = wsconn;
        conn->thread_index = thread_index;

        h2o_linklist_init_anchor(&conn->pending);

#ifdef DEBUG_SERIAL
        conn->clih.serial = __sync_fetch_and_add(&c->ws_serial_counter, 1);
// LOGD("%s() serial: %u websocket conn: %p wsconn: %p open", __FUNCTION__, conn->clih.serial, conn, wsconn);
#endif
        callback_on_ws_connected(conn);

        h2o_linklist_insert(&c->threads[thread_index].ws_conns, &conn->cmn.super.link);
    } else {
        struct notification_http_conn_t *conn = h2o_mem_alloc_pool(&req->pool, *conn, 1);
        memset(conn, 0x00, sizeof(*conn));


        conn->cmn.c = c;
        conn->thread_index = thread_index;
        conn->req.req = req;

#ifdef DEBUG_SERIAL
        conn->req.serial = __sync_fetch_and_add(&c->serial_counter, 1);
// LOGD("%s() serial: %u http req: %p conn: %p open", __FUNCTION__, conn->req.serial, req, conn);
#endif
        h2o_linklist_insert(&c->threads[thread_index].conns, &conn->node);
        callback_on_http_req(conn);
    }

    return 0;
}

static int num_connections(struct server_context_t *c, int delta)
{
    return __sync_fetch_and_add(&c->state._num_connections, delta);
}

static void on_socketclose(void *data)
{
    struct server_context_t *c = data;
    /* int prev = */ num_connections(c, -1);
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
    struct listener_ctx_t *ctx = listener->data;
    struct server_context_t *c = ctx->c;

    if (H2O_UNLIKELY(err != NULL)) {
        LOGW("%s() thread_index: %d err: %s", __FUNCTION__, get_current_thread_index(c), err);
        return;
    }

    {
        h2o_socket_t *sock;

        if ((sock = h2o_evloop_socket_accept(listener)) == NULL) {
            return;
        }
        // LOGD("%s() thread_index: %d sock: %p data: %p", __FUNCTION__, get_current_thread_index(c), sock, ctx->accept_ctx.ctx);

        num_connections(c, 1);

        sock->on_close.cb = on_socketclose;
        sock->on_close.data = c;
        h2o_accept(&ctx->accept_ctx, sock);
    }
}

static struct listener_config_t *find_listener(struct server_context_t *c, struct sockaddr *addr, socklen_t addrlen)
{
    size_t i;

    for (i = 0; i != c->num_listeners; ++i) {
        struct listener_config_t *listener = c->listeners[i];
        if (listener->addrlen == addrlen && h2o_socket_compare_address((void *)&listener->addr, addr) == 0)
            return listener;
    }

    return NULL;
}

static void remove_all_listeners(struct server_context_t *c)
{
    size_t i;

    for (i = 0; i != c->num_listeners; ++i) {
#if defined(__linux__) && defined(SO_REUSEPORT)
        if (c->listeners[i]->reuseport_fds)
            free(c->listeners[i]->reuseport_fds);
#endif
        free(c->listeners[i]);
    }
    free(c->listeners);
    c->num_listeners = 0;
}

static struct listener_config_t *add_listener(struct server_context_t *c, int fd, struct sockaddr *addr, socklen_t addrlen,
                                              int is_global, int proxy_protocol)
{
    struct listener_config_t *listener = h2o_mem_alloc(sizeof(*listener));
    memcpy(&listener->addr, addr, addrlen);
    listener->fd = fd;
#if defined(__linux__) && defined(SO_REUSEPORT)
    listener->reuseport_fds = NULL;
#endif

    listener->addrlen = addrlen;
    if (is_global) {
        listener->hosts = NULL;
    } else {
        listener->hosts = h2o_mem_alloc(sizeof(listener->hosts[0]));
        listener->hosts[0] = NULL;
    }
    listener->ssl_ctx = NULL;
    listener->proxy_protocol = proxy_protocol;

    c->listeners = h2o_mem_realloc(c->listeners, sizeof(*(c->listeners)) * (c->num_listeners + 1));
    c->listeners[c->num_listeners++] = listener;
    return listener;
}

static int open_tcp_listener(struct server_context_t *c, const char *hostname, const char *servname, int domain, int type,
                             int protocol, struct sockaddr *addr, socklen_t addrlen, int *so_reuseport)
{
    int fd;

    if ((fd = socket(domain, type, protocol)) == -1)
        goto Error;
    set_cloexec(fd);
    { /* set reuseaddr */
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#if defined(__linux__) && defined(SO_REUSEPORT)
    if (*so_reuseport) { /* set reuseport */
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) != 0) {
            LOGW("failed to set SO_REUSEPORT:%s", strerror(errno));
            *so_reuseport = 0;
        }
    }
#endif
#ifdef TCP_DEFER_ACCEPT
    { /* set TCP_DEFER_ACCEPT */
        int flag = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#endif
#ifdef IPV6_V6ONLY
    /* set IPv6only */
    if (domain == AF_INET6) {
        int flag = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#endif
    if (bind(fd, addr, addrlen) != 0)
        goto Error;
    if (listen(fd, H2O_SOMAXCONN) != 0)
        goto Error;

    /* set TCP_FASTOPEN; when tfo_queues is zero TFO is always disabled */
    if (c->tfo_queues > 0) {
#ifdef TCP_FASTOPEN
        int tfo_queues;
#ifdef __APPLE__
        /* In OS X, the option value for TCP_FASTOPEN must be 1 if is's enabled */
        tfo_queues = 1;
#else
        tfo_queues = c->tfo_queues;
#endif
        if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, (const void *)&tfo_queues, sizeof(tfo_queues)) != 0)
            LOGW("[warning] failed to set TCP_FASTOPEN:%s", strerror(errno));
#else
        ASSERT(!"conf.tfo_queues not zero on platform without TCP_FASTOPEN");
#endif
    }

    return fd;

Error:
    if (fd != -1)
        close(fd);
    LOGE("failed to listen to port %s:%s: %s", hostname != NULL ? hostname : "ANY", servname, strerror(errno));
    return -1;
}

static int create_listener(struct server_context_t *c)
{
    const char *hostname;
    const char **servname;
    int so_reuseport = 0;

    /* TCP socket */
    struct addrinfo hints, *res, *ai;
    int error;

    hostname = c->server_init.host;
    servname = c->server_init.port;

    while (*servname != NULL) {
        /* call getaddrinfo */
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
        if ((error = getaddrinfo(hostname, *servname, &hints, &res)) != 0) {
            LOGE("failed to resolve the listening address: %s", gai_strerror(error));
            return -1;
        } else if (res == NULL) {
            LOGE("failed to resolve the listening address: getaddrinfo returned an empty list");
            return -1;
        }
        /* listen to the returned addresses */
        for (ai = res; ai != NULL; ai = ai->ai_next) {
            struct listener_config_t *listener = find_listener(c, ai->ai_addr, ai->ai_addrlen);
            int listener_is_new = 0;
            if (listener == NULL) {
                int fd = -1;
#if defined(__linux__) && defined(SO_REUSEPORT)
                so_reuseport = 1;
#endif
                if ((fd = open_tcp_listener(c, hostname, *servname, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addr,
                                            ai->ai_addrlen, &so_reuseport)) == -1) {
                    freeaddrinfo(res);
                    return -1;
                }
                listener = add_listener(c, fd, ai->ai_addr, ai->ai_addrlen, 1, 0);
                LOGD("create_listener() fd: %d num_listeners: %u host: %s port: %s addrlen: %d (sa_family:%d)", fd,
                     (unsigned)c->num_listeners, hostname, *servname, ai->ai_addrlen, ai->ai_addr->sa_family);
                if (ai->ai_addr->sa_family == AF_INET) {
                    struct sockaddr_in *p = (struct sockaddr_in *)ai->ai_addr;
                    LOGD("inet_ntoa: %s port: %d", inet_ntoa(p->sin_addr), ntohs(p->sin_port));
                } else if (ai->ai_addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *p = (struct sockaddr_in6 *)ai->ai_addr;
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(ai->ai_addr->sa_family, &p->sin6_addr, str, sizeof(str));
                    LOGD("inet_ntop: %s pott: %d", str, ntohs(p->sin6_port));
                }

                listener_is_new = 1;
#if defined(__linux__) && defined(SO_REUSEPORT)
                /**
                 * socket open for all threads should before setuid() call when so_reuseport enabled
                 * in case of "user" has been configured.
                 * because: To prevent port hijacking all sockets bound to the same port using so_reuseport must have the
                 * same uid
                 */
                if (so_reuseport) {
                    size_t i;
                    listener->reuseport_fds = h2o_mem_alloc(sizeof(int) * c->server_init.num_threads);
                    listener->reuseport_fds[0] = fd;
                    for (i = 1; i < c->server_init.num_threads; ++i) {
                        if ((fd = open_tcp_listener(c, hostname, *servname, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
                                                    ai->ai_addr, ai->ai_addrlen, &so_reuseport)) == -1) {
                            freeaddrinfo(res);
                            return -1;
                        }
                        ASSERT(so_reuseport == 1);
                        listener->reuseport_fds[i] = fd;
                        LOGD("create_listener() so_reuseport fd: %d for thread: %u", fd, (unsigned)i);
                    }
                }
#endif
            }
            listener->hosts = c->config.hosts;

            listener->ssl_ctx = c->ssl_ctx;
        }
        /* release res */
        freeaddrinfo(res);
        servname++;
    }
    return 0;
}

static void setup_ecc_key(SSL_CTX *ssl_ctx)
{
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else
    int nid = NID_X9_62_prime256v1;
    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    if (key == NULL) {
        fprintf(stderr, "Failed to create curve \"%s\"\n", OBJ_nid2sn(nid));
        return;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
    EC_KEY_free(key);
#endif
}

static int libh2o_setup_ssl(struct server_context_t *c, const char *cert_file, const char *key_file, const char *ciphers)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    c->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(c->ssl_ctx, SSL_OP_NO_SSLv2);

    setup_ecc_key(c->ssl_ctx);

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_file(c->ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        LOGE("failed to load server certificate file: %s", cert_file);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(c->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        LOGE("failed to load private key file: %s", key_file);
        return -1;
    }
    if (SSL_CTX_set_cipher_list(c->ssl_ctx, ciphers) != 1) {
        LOGE("ciphers could not be set");
        return -1;
    }

/* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(c->ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(c->ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return 0;
}

static void update_listener_state(struct listener_ctx_t *listeners, size_t num_listeners)
{
    size_t i;

    for (i = 0; i != num_listeners; ++i) {
        if (!h2o_socket_is_reading(listeners[i].sock))
            h2o_socket_read_start(listeners[i].sock, on_accept);
    }
}

static void notify_threads_quit(struct server_context_t *c)
{
    int i;

    for (i = 0; i != c->server_init.num_threads; ++i) {
        struct notification_quit_t *msg = h2o_mem_alloc(sizeof(*msg));
        memset(msg, 0x00, sizeof(*msg));

        msg->cmn.cmd = NOTIFICATION_QUIT;
        msg->cmn.c = c;

        h2o_multithread_send_message(&c->threads[i].server_notifications, &msg->cmn.super);
    }
}

static void process_ready_req_item(struct notification_http_conn_t *conn)
{
    static h2o_generator_t generator = {NULL, NULL};
    int i;

    h2o_linklist_unlink(&conn->node);

    conn->req.req->res.status = conn->req.resp.status;
    conn->req.req->res.reason = conn->req.resp.reason != NULL ? conn->req.resp.reason : "OK";

    for (i = 0; i < HTTP_RESPONSE_HEADER_MAX; ++i) {
        if (conn->req.resp.header[i].token == NULL)
            break;
        h2o_add_header(&conn->req.req->pool, &conn->req.req->res.headers, conn->req.resp.header[i].token, NULL,
                       conn->req.resp.header[i].value.base, conn->req.resp.header[i].value.len);
    }
    h2o_start_response(conn->req.req, &generator);

    /**
     * conn->req.resp.body memory allocatd from is from conn->req.req->pool
     */
    h2o_send(conn->req.req, conn->req.resp.body.data, conn->req.resp.body.cnt, H2O_SEND_STATE_FINAL);
    callback_on_finish_http_req(conn);
}

static void release_notification_data(struct notification_data_t *msg)
{
    /* unlink from 'pending' */
    if (h2o_linklist_is_linked(&msg->cmn.super.link)) {
        h2o_linklist_unlink(&msg->cmn.super.link);
    }
    free(msg);
}

static void release_pending_data_linklist(struct notification_ws_conn_t *conn, int sent)
{
    h2o_linklist_t *messages = &conn->pending;
    struct server_context_t *c = conn->cmn.c;

    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, messages->next);
        struct notification_data_t *data = (struct notification_data_t *)msg;
        ASSERT(c == data->cmn.c);
        ASSERT(NOTIFICATION_WS_DATA == data->cmn.cmd);
        h2o_linklist_unlink(&msg->link);

        callback_on_ws_sent(conn, data->data.base, data->data.len, sent);
        release_notification_data(data);
    }
}

static void release_notification_ws_conn(struct notification_ws_conn_t *conn)
{
#ifdef DEBUG_SERIAL
    LOGV("release serial: %u", conn->clih.serial);
#endif
    if (h2o_timer_is_linked(&conn->dispose_timeout)) {
        h2o_timer_unlink(&conn->dispose_timeout);
    }

    ASSERT(h2o_linklist_is_linked(&conn->cmn.super.link));
    /* unlink from 'conns' */
    if (h2o_linklist_is_linked(&conn->cmn.super.link)) {
        h2o_linklist_unlink(&conn->cmn.super.link);
    }

    release_pending_data_linklist(conn, 0);

    /* release h2o websocket client conn */
    if (conn->wsconn) {
        h2o_websocket_close(conn->wsconn);
        conn->wsconn = NULL;
    }

    free(conn);
}

static void queue_websocket_data(struct notification_ws_conn_t *conn, struct notification_data_t *data)
{
    struct wslay_event_msg msgarg = {WSLAY_TEXT_FRAME, (const uint8_t *)data->data.base, data->data.len};

    if (data->conn) {
        ASSERT(conn == data->conn);
    }
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static void queue_websocket_close(struct notification_ws_conn_t *conn)
{
    struct wslay_event_msg msgarg = {WSLAY_CONNECTION_CLOSE, NULL, 0};
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static void queue_websocket_ping(struct notification_ws_conn_t *conn)
{
    struct wslay_event_msg msgarg = {WSLAY_PING, NULL, 0};
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static int queue_websocket_broadcast_cb(struct notification_ws_conn_t *conn, void *cbdata)
{
    if (conn->wsconn != NULL) {
        struct notification_data_t *data = cbdata;
        queue_websocket_data(conn, data);
        h2o_websocket_proceed(conn->wsconn);
    }
    return 0;
}

static int queue_websocket_close_cb(struct notification_ws_conn_t *conn, void *cbdata)
{
    if (conn->wsconn != NULL) {
        queue_websocket_close(conn);
        h2o_websocket_proceed(conn->wsconn);
    }
    return 0;
}

static int foreach_ws_conn(h2o_linklist_t *list, int (*cb)(struct notification_ws_conn_t *conn, void *cbdata), void *cbdata)
{
    h2o_linklist_t *node;

    for (node = list->next; node != list; node = node->next) {
        struct notification_ws_conn_t *conn = (struct notification_ws_conn_t *)(node);
        int ret = cb(conn, cbdata);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static void process_ws_broadcast(struct server_context_t *c, int thread_index, struct notification_data_t *data)
{
    foreach_ws_conn(&c->threads[thread_index].ws_conns, queue_websocket_broadcast_cb, data);
}

static void queue_ws_connection_close(struct server_context_t *c, int thread_index)
{
    foreach_ws_conn(&c->threads[thread_index].ws_conns, queue_websocket_close_cb, NULL);
}

static int foreach_ws_conn_safe(h2o_linklist_t *list, int (*cb)(struct notification_ws_conn_t *conn, void *cbdata), void *cbdata)
{
    h2o_linklist_t *node, *n;

    for (node = list->next, n = node->next; node != list; node = n, n = node->next) {
        struct notification_ws_conn_t *conn = (struct notification_ws_conn_t *)(node);
        int ret = cb(conn, cbdata);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static void on_server_notification(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, messages->next);
        struct notification_cmn_t *cmn = (struct notification_cmn_t *)msg;
        struct server_context_t *c = cmn->c;

        h2o_linklist_unlink(&msg->link);
        if (cmn->cmd == NOTIFICATION_WS_DATA) {
            struct notification_data_t *data = (struct notification_data_t *)cmn;
            struct notification_ws_conn_t *conn = data->conn;
            if (conn->wsconn != NULL) {
                queue_websocket_data(conn, data);
                h2o_websocket_proceed(conn->wsconn);
                callback_on_ws_sent(conn, data->data.base, data->data.len, 1);
                release_notification_data(data);
            } else {
                LOGW("caller want to send data without connection");
                h2o_linklist_insert(&conn->pending, &msg->link);
            }
        } else if (cmn->cmd == NOTIFICATION_HTTP_RESP) {
            struct notification_http_conn_t *conn = (struct notification_http_conn_t *)cmn;
            process_ready_req_item(conn);

        } else if (cmn->cmd == NOTIFICATION_WS_BROADCAST) {
            struct notification_data_t *data = (struct notification_data_t *)cmn;
            int thread_index = get_current_thread_index(c);

            ASSERT(data->conn == NULL);
            process_ws_broadcast(c, thread_index, data);
            free(data->data.base);
            release_notification_data(data);
        } else if (cmn->cmd == NOTIFICATION_QUIT) {
            int thread_index = get_current_thread_index(c);
            queue_ws_connection_close(c, thread_index);
            c->threads[thread_index].exit_loop = 1;
            free(msg);
        } else {
            ASSERT(0);
            free(msg);
        }
    }
}

static void *server_loop(void *_param)
{
    struct thread_param_t *param = _param;
    struct server_context_t *c = param->c;
    int thread_index = param->thread_index;
    struct listener_ctx_t *listeners;
    size_t i;

    LOGV("%s(%d)...", __FUNCTION__, thread_index);
    ASSERT(thread_index >= 0);

    free(_param);

    set_current_thread_index(c, thread_index);
    listeners = alloca(sizeof(*listeners) * c->num_listeners);

    h2o_context_init(&c->threads[thread_index].ctx, h2o_evloop_create(), &c->config);
    h2o_multithread_register_receiver(c->threads[thread_index].ctx.queue, &c->threads[thread_index].server_notifications,
                                      on_server_notification);
#if USE_MEMCACHED
    h2o_multithread_register_receiver(c->threads[thread_index].ctx.queue, &c->threads[thread_index].memcached,
                                      h2o_memcached_receiver);
#endif
    c->threads[thread_index].tid = pthread_self();

    /* setup listeners */
    for (i = 0; i != c->num_listeners; ++i) {
        struct listener_config_t *listener_config = c->listeners[i];
        int fd;
        /* dup the listener fd for other threads than the main thread */
        if (thread_index == 0) {
            fd = listener_config->fd;
#if defined(__linux__) && defined(SO_REUSEPORT)
            if (listener_config->reuseport_fds != NULL) {
                ASSERT(fd == listener_config->reuseport_fds[0]);
            }
#endif
        } else {
#if defined(__linux__) && defined(SO_REUSEPORT)
            if (listener_config->reuseport_fds != NULL) {
                fd = listener_config->reuseport_fds[thread_index];
                ASSERT(fd != -1);
            } else
#endif
                if ((fd = dup(listener_config->fd)) == -1) {
                LOGE("failed to dup listening socket");
            }
            set_cloexec(fd);
        }
        memset(listeners + i, 0, sizeof(listeners[i]));
        listeners[i].accept_ctx.ctx = &c->threads[thread_index].ctx;
        listeners[i].accept_ctx.hosts = listener_config->hosts;
        listeners[i].accept_ctx.ssl_ctx = listener_config->ssl_ctx;
        listeners[i].accept_ctx.expect_proxy_line = listener_config->proxy_protocol;
#if USE_MEMCACHED
        listeners[i].accept_ctx.libmemcached_receiver = &c->threads[thread_index].memcached;
#else
        listeners[i].accept_ctx.libmemcached_receiver = NULL;
#endif
        listeners[i].sock = h2o_evloop_socket_create(c->threads[thread_index].ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
        listeners[i].sock->data = listeners + i;
        listeners[i].c = c;
    }
    /* and start listening */
    update_listener_state(listeners, c->num_listeners);

    while (1) {
        if (c->threads[thread_index].exit_loop)
            break;
        h2o_evloop_run(c->threads[thread_index].ctx.loop, INT32_MAX);
    }
    if (thread_index == 0) {
        LOGD("shutting down...");
    }

    /* shutdown requested, unregister, close the listeners and notify the protocol handlers */
    for (i = 0; i != c->num_listeners; ++i)
        h2o_socket_read_stop(listeners[i].sock);
    h2o_evloop_run(c->threads[thread_index].ctx.loop, 0);

    while (!h2o_linklist_is_empty(&c->threads[thread_index].ws_conns)) {
        LOGD("ws_conn list is not empty, thread_index: %d", thread_index);
        h2o_evloop_run(c->threads[thread_index].ctx.loop, DISPOSE_TIMEOUT_MS);
    }

    h2o_context_request_shutdown(&c->threads[thread_index].ctx);

    /* wait until all the connection gets closed */
    while (num_connections(c, 0) != 0)
        h2o_evloop_run(c->threads[thread_index].ctx.loop, DISPOSE_TIMEOUT_MS);

    for (i = 0; i != c->num_listeners; ++i) {
        h2o_socket_close(listeners[i].sock);
        listeners[i].sock = NULL;
    }

    while (UINT64_MAX != h2o_timerwheel_get_wake_at(c->threads[thread_index].ctx.loop->_timeouts)) {
        LOGD("timeout is not empty, thread_index: %d", thread_index);
        // h2o_timerwheel_dump(c->threads[thread_index].ctx.loop->_timeouts);
        h2o_evloop_run(c->threads[thread_index].ctx.loop, DISPOSE_TIMEOUT_MS);
    }
    h2o_multithread_unregister_receiver(c->threads[thread_index].ctx.queue, &c->threads[thread_index].server_notifications);
#if USE_MEMCACHED
    h2o_multithread_unregister_receiver(c->threads[thread_index].ctx.queue, &c->threads[thread_index].memcached);
#endif

    h2o_context_dispose(&c->threads[thread_index].ctx);
    h2o_evloop_destroy(c->threads[thread_index].ctx.loop);

    /**
     * this will clean thread local data used by pool
     */
    h2o_cleanup_thread();

    return 0;
}

static void free_server_thread_data(struct server_context_t *c)
{
    if (c->threads) {
        free(c->threads);
        c->threads = NULL;
    }
}

const char *libh2o_http_server_get_version(void)
{
    return H2O_VERSION;
}

struct server_context_t *libh2o_http_server_start(const struct http_server_init_t *server_init)
{
    struct server_context_t *c;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
    struct server_handler_t *handler;

    int i;

    if (H2O_UNLIKELY(server_init->num_threads <= 0 || server_init->num_threads > 8)) {
        LOGE("invalid num_threads: %d", server_init->num_threads);
        return NULL;
    }

    if (H2O_UNLIKELY(server_init->host == NULL)) {
        LOGE("no host");
        return NULL;
    }

    if (H2O_UNLIKELY(server_init->port == NULL || *server_init->port == NULL)) {
        LOGE("no port");
        return NULL;
    }

    c = h2o_mem_alloc(sizeof(*c));
    memset(c, 0x00, sizeof(*c));

#if USE_HTTPS
    init_openssl();
#endif
    if (pthread_key_create(&c->tls, server_tls_destroy) != 0) {
        LOGE("pthread_key_create failed");
        return NULL;
    }

    h2o_config_init(&c->config);
    /* c->config.http1.req_timeout = 3000; */

    hostconf = h2o_config_register_host(&c->config, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    pathconf = h2o_config_register_path(hostconf, "/", 0);

    handler = (struct server_handler_t *)h2o_create_handler(pathconf, sizeof(*handler));
    handler->super.on_req = on_req;
    handler->super.dispose = on_handler_dispose;
    handler->c = c;

    LOGD("server_init: %s\nnum_threads: %d\ndoc_root: %s\nssl_init: %s %s %s", server_init->host, server_init->num_threads,
         server_init->doc_root, server_init->ssl_init.cert_file, server_init->ssl_init.key_file, server_init->ssl_init.ciphers);

    memcpy(&c->server_init, server_init, sizeof(*server_init));
    c->threads = h2o_mem_alloc(server_init->num_threads * sizeof(c->threads[0]));
    memset(c->threads, 0x00, server_init->num_threads * sizeof(c->threads[0]));
    c->tfo_queues = 4;
    c->state._num_connections = 0;

    for (i = 0; i < c->server_init.num_threads; ++i) {
        h2o_linklist_init_anchor(&c->threads[i].conns);
        h2o_linklist_init_anchor(&c->threads[i].ws_conns);
    }

#if USE_HTTPS
    if (libh2o_setup_ssl(c, server_init->ssl_init.cert_file, server_init->ssl_init.key_file, server_init->ssl_init.ciphers) != 0) {
        LOGE("failed to setup ssl");
        goto ERROR;
    }
#endif

    /* disabled by default: uncomment the line below to enable access logging */
    /* h2o_access_log_register(&config.default_host, "/dev/stdout", NULL); */

    if (create_listener(c) != 0) {
        LOGE("failed to listen to %s:%s: %s", c->server_init.host, c->server_init.port[0], strerror(errno));
        goto ERROR;
    }

    for (i = 0; i < c->server_init.num_threads; ++i) {
        struct thread_param_t *param = h2o_mem_alloc(sizeof(*param));
        param->thread_index = i;
        param->c = c;
        pthread_t tid;
        h2o_multithread_create_thread(&tid, NULL, server_loop, param);
    }

    return c;

ERROR:
    h2o_config_dispose(&c->config);
    remove_all_listeners(c);
    free_server_thread_data(c);
    return NULL;
}

void libh2o_http_server_stop(struct server_context_t *c)
{
    size_t i;

    if (c == NULL)
        return;

    notify_threads_quit(c);
    for (i = 0; i < c->server_init.num_threads; ++i) {
        pthread_join(c->threads[i].tid, NULL);
    }

    h2o_config_dispose(&c->config);
    remove_all_listeners(c);
    free_server_thread_data(c);
    pthread_key_delete(c->tls);
    free(c);
}

static void notify_thread_resp(struct notification_http_conn_t *conn)
{
    struct server_context_t *c;
    int thread_index;

    ASSERT(conn->cmn.c);
    ASSERT(!conn->cmn.cmd);

    c = conn->cmn.c;
    conn->cmn.cmd = NOTIFICATION_HTTP_RESP;

    thread_index = conn->thread_index;
    ASSERT(conn->thread_index >= 0 && conn->thread_index < c->server_init.num_threads);

    h2o_multithread_send_message(&c->threads[thread_index].server_notifications, &conn->cmn.super);
}

void libh2o_http_server_queue_response(struct http_request_t *req)
{
    struct notification_http_conn_t *conn;

    if (H2O_UNLIKELY(req == NULL)) {
        return;
    }

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_http_conn_t, req, req);
    notify_thread_resp(conn);
}

static void notify_thread_data(struct notification_ws_conn_t *conn, const void *buf, size_t len)
{
    struct server_context_t *c;
    int thread_index;
    struct notification_data_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    c = conn->cmn.c;
    msg->cmn.cmd = NOTIFICATION_WS_DATA;
    msg->cmn.c = c;

    msg->conn = conn;
    msg->data = h2o_iovec_init(buf, len);
#ifdef DEBUG_SERIAL
    msg->serial = (uint64_t)conn->clih.serial << 32 | __sync_fetch_and_add(&conn->serial_counter, 1);
#endif
    thread_index = conn->thread_index;
    ASSERT(conn->thread_index >= 0 && conn->thread_index < c->server_init.num_threads);

    h2o_multithread_send_message(&c->threads[thread_index].server_notifications, &msg->cmn.super);
}

size_t libh2o_http_server_queue_ws_message(struct websocket_handle_t *clih, const void *buf, size_t len)
{
    struct notification_ws_conn_t *conn;

    if (H2O_UNLIKELY(clih == NULL))
        return 0;

    if (H2O_UNLIKELY(buf == NULL || len == 0)) {
        return 0;
    }

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_ws_conn_t, clih, clih);

    notify_thread_data(conn, buf, len);
    return len;
}

static void notify_thread_broadcast(struct server_context_t *c, const void *buf, size_t len)
{
    size_t i;

    for (i = 0; i < c->server_init.num_threads; ++i) {
        struct notification_data_t *msg = h2o_mem_alloc(sizeof(*msg));
        memset(msg, 0x00, sizeof(*msg));

        msg->cmn.cmd = NOTIFICATION_WS_BROADCAST;
        msg->cmn.c = c;

        /* msg->conn = NULL; */
        void *ptr = h2o_mem_alloc(len);
        memcpy(ptr, buf, len);
        msg->data = h2o_iovec_init(ptr, len);
#ifdef DEBUG_SERIAL
        msg->serial = ((uint64_t)0xFFFFFFFF) << 32 | __sync_fetch_and_add(&c->broadcast_serial_counter, 1);
#endif
        h2o_multithread_send_message(&c->threads[i].server_notifications, &msg->cmn.super);
    }
}

size_t libh2o_http_server_broadcast_ws_message(struct server_context_t *c, const void *buf, size_t len)
{
    if (H2O_UNLIKELY(c == NULL))
        return 0;

    if (H2O_UNLIKELY(buf == NULL || len == 0)) {
        return 0;
    }

    notify_thread_broadcast(c, buf, len);
    return len;
}

#ifdef UNIT_TEST
#include <signal.h>

static int g_Aborted = 0;
static void handleSignal(int signo)
{
    g_Aborted = 1;
}

static void registerSigHandler()
{
#ifndef _WIN32
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignal;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif
}

static void http_server_on_http_request_cb(void *param, struct http_request_t *data)
{
    // LOGD("%s() req: %p", __FUNCTION__, data->req);

    data->resp.status = 200;
    data->resp.header[0].token = H2O_TOKEN_CONTENT_TYPE;
    data->resp.header[0].value = h2o_iovec_init(H2O_STRLIT("text/plain"));

    data->resp.body.cnt = 2;
    data->resp.body.data[0] = h2o_strdup(&data->req->pool, "hello world\n", SIZE_MAX);
    data->resp.body.data[1] = h2o_strdup(&data->req->pool, "test...\n", SIZE_MAX);

    libh2o_http_server_queue_response(data);
}

static void http_server_on_finish_http_request_cb(void *param, struct http_request_t *data)
{
    // LOGD("%s() req: %p", __FUNCTION__, data->req);
    /*FIXME: data->req->http1_is_persistent = 0; */
}

static void http_server_on_ws_recv_cb(void *param, void *buf, size_t len, struct websocket_handle_t *clih)
{
    const char *p = "hello websocket client";

    // fwrite(buf, 1, len, stdout);
    libh2o_http_server_queue_ws_message(clih, strdup(p), strlen(p) + 1);
}

static void http_server_on_ws_sent_cb(void *param, void *buf, size_t len, struct websocket_handle_t *clih)
{
    free(buf);
}

static void http_server_on_ws_connected_cb(void *param, struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

static void http_server_on_ws_connection_closed_cb(void *param, struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

int main(int argc, char *argv[])
{
    struct server_context_t *c;

    struct http_server_init_t server_init;
    const char *ports[3];
    ports[0] = "7890";
    ports[1] = "7891";
    ports[2] = NULL;

    server_init.num_threads = 2;
    server_init.host = "0.0.0.0";
    /* server_init.host = "ip6-localhost"; */
    server_init.port = ports;
    server_init.doc_root = "/";
    server_init.ssl_init.cert_file = "examples/h2o/server.crt";
    server_init.ssl_init.key_file = "examples/h2o/server.key";
    server_init.ssl_init.ciphers = "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK";

    server_init.cb.param = NULL;
    server_init.cb.on_http_req = http_server_on_http_request_cb;
    server_init.cb.on_finish_http_req = http_server_on_finish_http_request_cb;
    server_init.cb.on_ws_connected = http_server_on_ws_connected_cb;
    server_init.cb.on_ws_recv = http_server_on_ws_recv_cb;
    server_init.cb.on_ws_sent = http_server_on_ws_sent_cb;
    server_init.cb.on_ws_closed = http_server_on_ws_connection_closed_cb;

    signal(SIGPIPE, SIG_IGN);

    registerSigHandler();

#if 0
    int i;

    for (i = 0; i < 20; ++i) {
        c = libh2o_http_server_start(&server_init);
        int rc = usleep(1000000);

        libh2o_http_server_stop(c);
    }

#else
    c = libh2o_http_server_start(&server_init);

    while (!g_Aborted) {
        int rc = usleep(1000000);
        if (rc < 0 && errno == EINTR) {
            break;
        }
        const char *p = "hello websocket boradcast\n";
        libh2o_http_server_broadcast_ws_message(c, p, strlen(p) + 1);
    }

    libh2o_http_server_stop(c);
#endif
    return 0;
}

#endif
