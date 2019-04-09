/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_socket_server.c
 *   CREATE DATE : 2019-04-08
 *   MODULE      : libh2o_socket_server
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

#ifndef LOG_TAG
#define LOG_TAG "libh2o.socketserver"
#endif

// #define LOG_NDEBUG 0
/****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "h2o.h"

#include "libh2o_log.h"
#include "libh2o_cmn.h"
#include "libh2o_socket_server.h"

/****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#define DEBUG_SERIAL 1

#define NOTIFICATION_LISTEN 0
#define NOTIFICATION_CONN 1
#define NOTIFICATION_DATA 2
#define NOTIFICATION_CLOSE 3
#define NOTIFICATION_QUIT 0xFFFFFFFF

#define DISPOSE_TIMEOUT_MS 1000

/****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
/**
 * socket server context type
 */
struct libh2o_socket_server_ctx_t {
    pthread_t tid;
    h2o_sem_t sem;
    h2o_loop_t *loop;
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t notifications;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_linklist_t conns;
    h2o_linklist_t listeners;
    struct socket_server_init_t server_init;
    SSL_CTX *ssl_ctx;
    int exit_loop;
    uint32_t serial_counter; /* listener serial counter */
};

/**
 * MUST the first member for sub struct
 */
struct notification_cmn_t {
    h2o_multithread_message_t
        super; /* used to call h2o_multithread_send_message() */
    struct libh2o_socket_server_ctx_t *c;
    uint32_t cmd;
};

struct notification_listen_t {
    struct notification_cmn_t cmn;
    h2o_hostinfo_getaddr_req_t *hostinfo_req;
    h2o_socket_t *sock;
    uint32_t serial_counter; /* connection serial counter */
    struct socket_server_req_t req;
    struct socket_server_handle_t clih;
};

struct notification_conn_t {
    struct notification_cmn_t cmn;
    h2o_linklist_t pending; /* list for pending data waiting for sending */
    h2o_linklist_t sending; /* list for current sentding data */
    h2o_socket_t *sock;
    h2o_timer_t _timeout;
    struct socket_server_handle_t clih;
    struct notification_listen_t *listener;
};

struct notification_quit_t {
    struct notification_cmn_t cmn;
};

struct notification_data_t {
    struct notification_cmn_t cmn;
    struct notification_conn_t *conn;
    h2o_iovec_t data;
};

struct notification_close_t {
    struct notification_cmn_t cmn;
    struct notification_conn_t *conn;
};

/****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/

/****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/
static void on_write(h2o_socket_t *sock, const char *err);

static void dispose_timeout_cb(h2o_timer_t *entry);
static void write_timeout_cb(h2o_timer_t *entry);

/****************************************************************************
 *                       Functions Implement Section                         *
 *****************************************************************************/
static void notify_thread_quit(struct libh2o_socket_server_ctx_t *c)
{
    struct notification_quit_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_QUIT;
    msg->cmn.c = c;

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
}

static struct notification_listen_t *
notify_thread_listen(struct libh2o_socket_server_ctx_t *c,
                     const struct socket_server_req_t *req, void *user)
{
    struct notification_listen_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_LISTEN;
    msg->cmn.c = c;

    /* server handle */
    msg->clih.serial = __sync_add_and_fetch(&c->serial_counter, 1);
    msg->clih.user = user;
#ifdef DEBUG_SERIAL
    LOGV("create serial: %u", (uint32_t)msg->clih.serial);
#endif

    /* request */
    memcpy(&msg->req, req, sizeof(*req));

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
    return msg;
}

static void notify_thread_data(struct notification_conn_t *conn,
                               const void *buf, size_t len)
{
    struct notification_data_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_DATA;
    msg->cmn.c = conn->cmn.c;

    msg->conn = conn;
    msg->data = h2o_iovec_init(buf, len);

    h2o_multithread_send_message(&conn->cmn.c->notifications, &msg->cmn.super);
}

static void notify_thread_release(struct notification_conn_t *conn)
{
    struct notification_close_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_CLOSE;
    msg->cmn.c = conn->cmn.c;

    msg->conn = conn;

    h2o_multithread_send_message(&conn->cmn.c->notifications, &msg->cmn.super);
}

static void callback_on_connected(struct notification_conn_t *conn)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    struct socket_server_init_t *p = &c->server_init;

    if (p->cb.on_connected) {
        p->cb.on_connected(p->cb.param, &conn->clih);
    }
}

static void callback_on_data(struct notification_conn_t *conn, void *buf,
                             size_t len)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    struct socket_server_init_t *p = &c->server_init;

    if (p->cb.on_data) {
        p->cb.on_data(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_sent(struct notification_conn_t *conn, void *buf,
                             size_t len, int sent)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    struct socket_server_init_t *p = &c->server_init;

    if (p->cb.on_sent) {
        p->cb.on_sent(p->cb.param, buf, len, sent, &conn->clih);
    }
}

static void callback_on_closed(struct notification_conn_t *conn,
                               const char *err)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    struct socket_server_init_t *p = &c->server_init;

    if (p->cb.on_closed) {
        p->cb.on_closed(p->cb.param, err, &conn->clih);
    }
}

static void release_notification_data(struct notification_data_t *msg)
{
    if (h2o_linklist_is_linked(&msg->cmn.super.link)) {
        h2o_linklist_unlink(&msg->cmn.super.link);
    }
    free(msg);
}

static void release_data_linkedlist(struct notification_conn_t *conn,
                                    h2o_linklist_t *messages, int sent)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;

    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_data_t *data = (struct notification_data_t *)msg;
        ASSERT(c == data->cmn.c);
        ASSERT(NOTIFICATION_DATA == data->cmn.cmd);
        h2o_linklist_unlink(&msg->link);

        callback_on_sent(conn, data->data.base, data->data.len, sent);
        release_notification_data(data);
    }
}

static void release_sending(struct notification_conn_t *conn)
{
    release_data_linkedlist(conn, &conn->sending, 1);
}

static void do_socket_write(struct notification_conn_t *conn,
                            struct notification_data_t *data)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;

    /**
     * link to sending list and send
     */
    h2o_linklist_insert(&conn->sending, &data->cmn.super.link);

    if (c->server_init.io_timeout > 0) {
        /* I/O timeout */
        conn->_timeout.cb = write_timeout_cb;
        h2o_timer_link(c->loop, c->server_init.io_timeout, &conn->_timeout);
    }

    h2o_socket_write(conn->sock, &data->data, 1, on_write);
}

static void write_pending(struct notification_conn_t *conn)
{
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    h2o_linklist_t *messages = &conn->pending;
    h2o_multithread_message_t *msg;
    struct notification_data_t *data;

    if (h2o_linklist_is_empty(messages)) {
        return;
    }

    ASSERT(!h2o_socket_is_writing(conn->sock));
    if (h2o_socket_is_writing(conn->sock)) {
        return;
    }

    /**
     * remove one message from pending list
     * FIXME: we can remove more message for single write
     */
    msg =
        H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, messages->next);
    data = (struct notification_data_t *)msg;
    ASSERT(c == data->cmn.c);
    ASSERT(NOTIFICATION_DATA == data->cmn.cmd);
    h2o_linklist_unlink(&msg->link);

    do_socket_write(conn, data);
}

static void release_notification_conn(struct notification_conn_t *conn)
{
#ifdef DEBUG_SERIAL
    LOGV("release serial: %lld", (long long)conn->clih.serial);
#endif
    if (h2o_timer_is_linked(&conn->_timeout)) {
        h2o_timer_unlink(&conn->_timeout);
    }

    /* unlink from 'conns' */
    if (h2o_linklist_is_linked(&conn->cmn.super.link)) {
        h2o_linklist_unlink(&conn->cmn.super.link);
    }

    release_data_linkedlist(conn, &conn->pending, 0);
    release_data_linkedlist(conn, &conn->sending, 0);

    if (conn->sock) {
        h2o_socket_close(conn->sock);
        conn->sock = NULL;
    }
    free(conn);
}

static void dispose_timeout_cb(h2o_timer_t *entry)
{
    struct notification_conn_t *conn;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, _timeout, entry);
    release_notification_conn(conn);
}

static void release_notification_listen(struct notification_listen_t *conn)
{
    if (conn->hostinfo_req) {
        h2o_hostinfo_getaddr_cancel(conn->hostinfo_req);
        conn->hostinfo_req = NULL;
    }
    if (conn->sock) {
        h2o_socket_close(conn->sock);
        conn->sock = NULL;
    }
    free(conn);
}

static void on_listener_error(struct notification_listen_t *conn,
                              const char *prefix, const char *err)
{
    ASSERT(err != NULL);

    LOGW("%s:%s", prefix, err);

    h2o_linklist_unlink(&conn->cmn.super.link);
    release_notification_listen(conn);
}

static void on_error(struct notification_conn_t *conn, const char *prefix,
                     const char *err)
{
    struct libh2o_socket_server_ctx_t *c;
    ASSERT(err != NULL);

    LOGW("%s:%s", prefix, err);

    /* if connec timeout pending, unlink it first */
    if (h2o_timer_is_linked(&conn->_timeout)) {
        h2o_timer_unlink(&conn->_timeout);
    }

    callback_on_closed(conn, err);
    if (conn->sock) {
        h2o_socket_close(conn->sock);
        conn->sock = NULL;
    }

    c = conn->cmn.c;
    conn->_timeout.cb = dispose_timeout_cb;
    h2o_timer_link(c->loop, DISPOSE_TIMEOUT_MS, &conn->_timeout);
}

static void write_timeout_cb(h2o_timer_t *entry)
{
    struct notification_conn_t *conn;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, _timeout, entry);
    h2o_timer_unlink(&conn->_timeout);
    on_error(conn, "write_timeout_cb", "I/O timeout");
}

static void on_read(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn = sock->data;

    if (err != NULL) {
        /* read failed */
        on_error(conn, "on_read", err);
        return;
    }

    callback_on_data(conn, sock->input->bytes, sock->input->size);
    h2o_buffer_consume(&sock->input, sock->input->size);

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "on_read", "User close");
        return;
    }
}

static void on_write(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn = sock->data;

    if (h2o_timer_is_linked(&conn->_timeout)) {
        h2o_timer_unlink(&conn->_timeout);
    }

    if (err != NULL) {
        /* write failed */
        on_error(conn, "on_write", err);
        return;
    }

    release_sending(conn);

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "on_write", "User close");
        return;
    }

    write_pending(conn);
}

static struct notification_conn_t *
create_connection(struct notification_listen_t *conn)
{
    struct notification_conn_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.c = conn->cmn.c;
    msg->cmn.cmd = NOTIFICATION_CONN;

    msg->listener = conn;

    h2o_linklist_init_anchor(&msg->pending);
    h2o_linklist_init_anchor(&msg->sending);

    /* client handle */
    msg->clih.serial = conn->clih.serial << 32 |
                       __sync_add_and_fetch(&conn->serial_counter, 1);
    msg->clih.user = conn->clih.user;

#ifdef DEBUG_SERIAL
    LOGV("create serial: %lld", (long long)msg->clih.serial);
#endif

    h2o_linklist_insert(&conn->cmn.c->conns, &msg->cmn.super.link);
    return msg;
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn;

    if (err != NULL) {
        /* TLS handshake failed */
        LOGW("on_handshake_complete: %s", err);
        h2o_socket_close(sock);
        return;
    }

    conn = create_connection(sock->data);
    conn->sock = sock;
    sock->data = conn;
    callback_on_connected(conn);
    h2o_socket_read_start(sock, on_read);
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
    struct notification_listen_t *conn = listener->data;
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    h2o_socket_t *sock;

    if (err != NULL) {
        on_listener_error(conn, "on_accept", err);
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) != NULL) {
        sock->data = conn;
        if (c->ssl_ctx != NULL) {
            h2o_socket_ssl_handshake(sock, c->ssl_ctx, NULL,
                                     h2o_iovec_init(NULL, 0),
                                     on_handshake_complete);
        } else {
            on_handshake_complete(sock, NULL);
        }
    }
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *err,
                       struct addrinfo *res, void *_conn)
{
    struct notification_listen_t *conn = (struct notification_listen_t *)_conn;
    struct libh2o_socket_server_ctx_t *c = conn->cmn.c;
    h2o_socket_t *sock;
    struct addrinfo *selected;

    conn->hostinfo_req = NULL;
    if (err != NULL) {
        /* resolve host failed */
        on_listener_error(conn, "on_getaddr", err);
        return;
    }

    selected = h2o_hostinfo_select_one(res);

    int fd, reuseaddr_flag = 1;
    fd = socket(selected->ai_family,
                selected->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag,
               sizeof(reuseaddr_flag));

    bind(fd, res->ai_addr, res->ai_addrlen);
    listen(fd, 64);

    sock = h2o_evloop_socket_create(c->loop, fd, H2O_SOCKET_FLAG_DONT_READ);

    if (sock == NULL) {
        /* create socket failed */
        on_listener_error(conn, "on_getaddr", strerror(errno));
        return;
    }
    sock->data = conn;
    conn->sock = sock;
    h2o_socket_read_start(sock, on_accept);
    return;
}

static int foreach_conn(struct libh2o_socket_server_ctx_t *c,
                        int (*cb)(struct notification_conn_t *conn,
                                  void *cbdata),
                        void *cbdata)
{
    h2o_linklist_t *node;

    for (node = c->conns.next; node != &c->conns; node = node->next) {
        struct notification_conn_t *conn = (struct notification_conn_t *)(node);
        int ret = cb(conn, cbdata);
        if (ret != 0) return ret;
    }
    return 0;
}

static void release_conn_linkedlist(struct libh2o_socket_server_ctx_t *c,
                                    h2o_linklist_t *messages, const char *err)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_conn_t *conn = (struct notification_conn_t *)msg;
        ASSERT(c == conn->cmn.c);
        h2o_linklist_unlink(&msg->link);

        callback_on_closed(conn, err);
        release_notification_conn(conn);
    }
}

static void release_conns(struct libh2o_socket_server_ctx_t *c, const char *err)
{
    release_conn_linkedlist(c, &c->conns, err);
}

static void release_listen_linkedlist(struct libh2o_socket_server_ctx_t *c,
                                      h2o_linklist_t *messages, const char *err)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_listen_t *conn =
            (struct notification_listen_t *)msg;
        ASSERT(c == conn->cmn.c);
        h2o_linklist_unlink(&msg->link);

        release_notification_listen(conn);
    }
}

static void release_listeners(struct libh2o_socket_server_ctx_t *c,
                              const char *err)
{
    release_listen_linkedlist(c, &c->listeners, err);
}

static void on_notification(h2o_multithread_receiver_t *receiver,
                            h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_cmn_t *cmn = (struct notification_cmn_t *)msg;
        struct libh2o_socket_server_ctx_t *c = cmn->c;

        h2o_linklist_unlink(&msg->link);
        if (cmn->cmd == NOTIFICATION_DATA) {
            struct notification_data_t *data =
                (struct notification_data_t *)cmn;
            struct notification_conn_t *conn = data->conn;
            if (conn->sock == NULL) {
                LOGW("caller want to send data without connection");
                h2o_linklist_insert(&conn->pending, &msg->link);
            } else if (!h2o_socket_is_writing(conn->sock)) {
                do_socket_write(conn, data);
            } else {
                h2o_linklist_insert(&conn->pending, &msg->link);
            }
        } else if (cmn->cmd == NOTIFICATION_LISTEN) {
            struct notification_listen_t *conn =
                (struct notification_listen_t *)cmn;
            h2o_iovec_t iov_name =
                h2o_iovec_init(conn->req.host, strlen(conn->req.host));

            const char *to_sun_err;
            struct sockaddr_un sa;

            h2o_linklist_insert(&c->listeners, &msg->link);

            to_sun_err = h2o_url_host_to_sun(iov_name, &sa);
            if (to_sun_err == NULL) {
                h2o_socket_t *sock;
                int fd = socket(AF_UNIX,
                                SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                bind(fd, (const struct sockaddr *)&sa, sizeof(sa));
                listen(fd, 64);
                sock = h2o_evloop_socket_create(c->loop, fd,
                                                H2O_SOCKET_FLAG_DONT_READ);
                if (sock == NULL) {
                    /* create socket failed */
                    on_listener_error(conn, "on_notification", strerror(errno));
                } else {
                    sock->data = conn;
                    conn->sock = sock;
                    h2o_socket_read_start(sock, on_accept);
                }
            } else {
                h2o_iovec_t iov_serv =
                    h2o_iovec_init(conn->req.port, strlen(conn->req.port));

                /* resolve host name */
                conn->hostinfo_req = h2o_hostinfo_getaddr(
                    &c->getaddr_receiver, iov_name, iov_serv, AF_UNSPEC,
                    SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV,
                    on_getaddr, conn);
            }

        } else if (cmn->cmd == NOTIFICATION_CLOSE) {
            struct notification_close_t *data =
                (struct notification_close_t *)cmn;
            struct notification_conn_t *conn = data->conn;
            conn->cmn.cmd = NOTIFICATION_CLOSE;
            if (conn->sock == NULL) {
                LOGW("caller want to close without connection");
            } else if (!h2o_socket_is_writing(conn->sock)) {
                on_error(conn, "on_notification", "User close");
            } else {
            }
            free(msg);

        } else if (cmn->cmd == NOTIFICATION_QUIT) {
            c->exit_loop = 1;
            free(msg);
        } else {
            ASSERT(0);
            free(msg);
        }
    }
}

static int cli_key_file_passwd_cb(char *buf, int size, int rwflag, void *u)
{
    struct libh2o_socket_server_ctx_t *c = u;

    if (c->server_init.ssl_init.passwd_cb) {
        return c->server_init.ssl_init.passwd_cb(buf, size, rwflag,
                                                 c->server_init.cb.param);
    }
    ASSERT(0);
    return 0;
}

static void init_openssl(struct libh2o_socket_server_ctx_t *c)
{
    if (c->server_init.ssl_init.cert_file) {
        int rc;

        libh2o_ssl_init();

        c->ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());

        SSL_CTX_use_certificate_chain_file(c->ssl_ctx,
                                           c->server_init.ssl_init.cert_file);
        if (c->server_init.ssl_init.key_file) {
            int type = SSL_FILETYPE_PEM;
            const char *p = strchr(c->server_init.ssl_init.key_file, '.');
            if (p != NULL) {
                if (strncasecmp(p + 1, "der", 3) == 0) {
                    type = SSL_FILETYPE_ASN1;
                }
            }
            SSL_CTX_set_default_passwd_cb(c->ssl_ctx, cli_key_file_passwd_cb);
            SSL_CTX_set_default_passwd_cb_userdata(c->ssl_ctx, c);
            rc = SSL_CTX_use_PrivateKey_file(
                c->ssl_ctx, c->server_init.ssl_init.key_file, type);
            ASSERT(rc > 0);
            if (rc <= 0) {
                LOGW("Error setting the key file");
                goto ERROR;
            }
        }
    }

    return;

ERROR:
    c->exit_loop = 1;
    return;
}

static void release_openssl(struct libh2o_socket_server_ctx_t *c)
{
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
    }
}

static void *server_loop(void *arg)
{
    struct libh2o_socket_server_ctx_t *c = arg;

#ifdef H2O_THREAD_LOCAL_UNINITIALIZED
    h2o_init_thread();
#endif

    c->loop = h2o_evloop_create();

    c->queue = h2o_multithread_create_queue(c->loop);
    h2o_multithread_register_receiver(c->queue, &c->getaddr_receiver,
                                      h2o_hostinfo_getaddr_receiver);
    h2o_multithread_register_receiver(c->queue, &c->notifications,
                                      on_notification);
    h2o_sem_post(&c->sem);

    init_openssl(c);

    while (!c->exit_loop) {
        h2o_evloop_run(c->loop, INT32_MAX);
    }

    release_listeners(c, "event loop quiting");
    ASSERT(h2o_linklist_is_empty(&c->listeners));

    while (!h2o_linklist_is_empty(&c->conns)) {
        h2o_evloop_run(c->loop, DISPOSE_TIMEOUT_MS);
    }

    ASSERT(h2o_linklist_is_empty(&c->conns));
    release_conns(c, "event loop quiting");
    release_openssl(c);

    h2o_multithread_unregister_receiver(c->queue, &c->getaddr_receiver);
    h2o_multithread_unregister_receiver(c->queue, &c->notifications);
    h2o_multithread_destroy_queue(c->queue);

    h2o_evloop_destroy(c->loop);

    /**
     * this will clean thread local data used by pool
     */
    h2o_cleanup_thread();
    return 0;
}

const char *libh2o_socket_server_get_version(void) { return H2O_VERSION; }

struct libh2o_socket_server_ctx_t *
libh2o_socket_server_start(const struct socket_server_init_t *server_init)
{
    struct libh2o_socket_server_ctx_t *c;

    if (!server_init) return NULL;

    if (server_init->ssl_init.cert_file) {
        if (!server_init->ssl_init.key_file) {
            LOGW("missing server key file");
            return NULL;
        }
    }

    c = h2o_mem_alloc(sizeof(*c));
    if (c) {
        memset(c, 0x00, sizeof(*c));

        h2o_linklist_init_anchor(&c->conns);
        h2o_linklist_init_anchor(&c->listeners);
        memcpy(&c->server_init, server_init, sizeof(*server_init));

        h2o_sem_init(&c->sem, 0);
        h2o_multithread_create_thread(&c->tid, NULL, server_loop, (void *)c);
        h2o_sem_wait(&c->sem);
    }

    return c;
}

void libh2o_socket_server_stop(struct libh2o_socket_server_ctx_t *c)
{
    if (!c) return;

    notify_thread_quit(c);
    pthread_join(c->tid, NULL);
    h2o_sem_destroy(&c->sem);
    free(c);
}

const struct socket_server_handle_t *
libh2o_socket_server_req(struct libh2o_socket_server_ctx_t *c,
                         const struct socket_server_req_t *req, void *user)
{
    struct notification_listen_t *conn;

    if (c == NULL || req == NULL) return NULL;

    if (req->host == NULL) {
        return NULL;
    }

    if (strncmp(req->host, "unix:", 5) == 0) {
        struct sockaddr_un sa;
        if (strlen(req->host) - 6 > sizeof(sa.sun_path)) return NULL;
    } else if (req->port == NULL) {
        return NULL;
    }
    conn = notify_thread_listen(c, req, user);
    return &conn->clih;
}

size_t libh2o_socket_server_send(const struct socket_server_handle_t *clih,
                                 const void *buf, size_t len)
{
    struct notification_conn_t *conn;

    if (clih == NULL) return 0;
    if (buf == NULL || len == 0) return 0;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);

    notify_thread_data(conn, buf, len);
    return len;
}

void libh2o_socket_server_release(const struct socket_server_handle_t *clih)
{
    struct notification_conn_t *conn;

    if (clih == NULL) return;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);

    notify_thread_release(conn);
}

#ifdef LIBH2O_UNIT_TEST
#include <signal.h>

struct socket_server_state_t {
    const struct socket_server_handle_t *clih;
};

struct sock_servers_t {
    struct libh2o_socket_server_ctx_t *c;
    int nservers;
    struct socket_server_state_t *servers;
};

struct sock_servers_t sock_clients;

static void
cb_socket_server_on_connected(void *param,
                              const struct socket_server_handle_t *clih)
{
    LOGV("%s() @line: %d clih: %p", __FUNCTION__, __LINE__, clih);
    struct sock_servers_t *ss = param;
}

static void cb_socket_server_on_data(void *param, void *buf, size_t len,
                                     const struct socket_server_handle_t *clih)
{
    struct sock_servers_t *ss = param;
    (void)ss;
    fwrite(buf, 1, len, stdout);
}

static void cb_socket_server_on_sent(void *param, void *buf, size_t len,
                                     int sent,
                                     const struct socket_server_handle_t *clih)
{
    struct sock_servers_t *ss = param;
    (void)ss;
    free(buf);
}

static void
cb_socket_server_on_closed(void *param, const char *err,
                           const struct socket_server_handle_t *clih)
{
    LOGV("%s() @line: %d clih: %p", __FUNCTION__, __LINE__, clih);
    struct sock_servers_t *ss = param;
}

int main(int argc, char **argv)
{
    /**
     * test with 'nc -l 1234'
     */
    struct sock_servers_t servers;
    int running = 1;

    signal(SIGPIPE, SIG_IGN);

    /**
     * server init param
     */
    struct socket_server_init_t server_init;
    memset(&server_init, 0x00, sizeof(server_init));

    server_init.cb.on_connected = cb_socket_server_on_connected;
    server_init.cb.on_data = cb_socket_server_on_data;
    server_init.cb.on_sent = cb_socket_server_on_sent;
    server_init.cb.on_closed = cb_socket_server_on_closed;
    server_init.cb.param = &servers;

    /**
     * 1: create socket server context
     * event loop thread will be created
     */
    servers.c = libh2o_socket_server_start(&server_init);

    servers.nservers = argc;
    servers.servers = malloc(sizeof(struct socket_server_state_t) * argc);
    memset(servers.servers, 0x00, sizeof(struct socket_server_state_t) * argc);

    /**
     * 2: create socket server request
     * on connected will be called back
     */
    struct socket_server_req_t req = {"127.0.0.1", "1234"};
    servers.servers[0].clih = libh2o_socket_server_req(servers.c, &req, NULL);

    int i;
    for (i = 1; i < argc; ++i) {
        req.host = argv[i];
        servers.servers[i].clih =
            libh2o_socket_server_req(servers.c, &req, NULL);
    }

    while (running) {
        if (usleep(1000000) < 0) break;
    }
    libh2o_socket_server_stop(servers.c);

    free(servers.servers);
    return 0;
}
#endif
