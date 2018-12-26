/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_socket_client.c
*   CREATE DATE : 2018-12-10
*   MODULE      : libh2o_socket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/

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

#include "libh2o_socket_client.h"

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/
#define DEBUG_SERIAL 1

#define NOTIFICATION_CONN 0
#define NOTIFICATION_DATA 1
#define NOTIFICATION_CLOSE 2
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

/****************************************************************************
*                       Type Definition Section                             *
*****************************************************************************/
/**
 * socket client context type
 */
struct libh2o_socket_client_ctx_t {
    pthread_t tid;
    h2o_loop_t *loop;
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t notifications;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_linklist_t conns;
    struct socket_client_init_t client_init;
    SSL_CTX *ssl_ctx;
    int exit_loop;
    uint32_t serial_counter; /* connection serial counter */
};

/**
 * MUST the first member for sub struct
 */
struct notification_cmn_t {
    h2o_multithread_message_t
        super; /* used to call h2o_multithread_send_message() */
    struct libh2o_socket_client_ctx_t *c;
    uint32_t cmd;
};

struct notification_conn_t {
    struct notification_cmn_t cmn;
    h2o_linklist_t pending; /* list for pending data waiting for sending */
    h2o_linklist_t sending; /* list for current sentding data */
    h2o_socket_t *sock;
    h2o_timer_t _timeout;
#ifdef ENABLE_DATA_SERIAL
    uint32_t serial_counter; /* data serial counter */
#endif
    struct socket_client_req_t req;
    struct socket_client_handle_t clih;
};

struct notification_quit_t {
    struct notification_cmn_t cmn;
};

struct notification_data_t {
    struct notification_cmn_t cmn;
    struct notification_conn_t *conn;
    h2o_iovec_t data;
#ifdef ENABLE_DATA_SERIAL
    uint64_t serial;
#endif
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
static void conn_timeout_cb(h2o_timer_t *entry);

/****************************************************************************
*                       Functions Implement Section                         *
*****************************************************************************/
static void notify_thread_quit(struct libh2o_socket_client_ctx_t *c)
{
    struct notification_quit_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_QUIT;
    msg->cmn.c = c;

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
}

static struct notification_conn_t *
notify_thread_connect(struct libh2o_socket_client_ctx_t *c,
                      const struct socket_client_req_t *req)
{
    struct notification_conn_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_CONN;
    msg->cmn.c = c;

    h2o_linklist_init_anchor(&msg->pending);
    h2o_linklist_init_anchor(&msg->sending);

    /* client handle */
    msg->clih.serial = __sync_fetch_and_add(&c->serial_counter, 1);
#ifdef DEBUG_SERIAL
    LOGV("create serial: %u", msg->clih.serial);
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
#ifdef ENABLE_DATA_SERIAL
    msg->serial = (uint64_t)conn->clih.serial << 32 |
                  __sync_fetch_and_add(&conn->serial_counter, 1);
// LOGV("create data serial: %lld", (long long)msg->serial);
#endif

    msg->data = h2o_iovec_init(buf, len);

    h2o_multithread_send_message(&conn->cmn.c->notifications, &msg->cmn.super);
}

static void notify_thread_release(struct notification_conn_t *conn)
{
    struct notification_data_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_CLOSE;
    msg->cmn.c = conn->cmn.c;

    msg->conn = conn;

    h2o_multithread_send_message(&conn->cmn.c->notifications, &msg->cmn.super);
}

static void callback_on_host_resolved(struct notification_conn_t *conn,
                                      struct addrinfo *addr)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    struct socket_client_init_t *p = &c->client_init;

    if (p->cb.on_host_resolved) {
        p->cb.on_host_resolved(p->cb.param, addr, &conn->clih);
    }
}

static void callback_on_connected(struct notification_conn_t *conn)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    struct socket_client_init_t *p = &c->client_init;

    if (p->cb.on_connected) {
        p->cb.on_connected(p->cb.param, &conn->clih);
    }
}

static void callback_on_data(struct notification_conn_t *conn, void *buf,
                             size_t len)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    struct socket_client_init_t *p = &c->client_init;

    if (p->cb.on_data) {
        p->cb.on_data(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_sent(struct notification_conn_t *conn, void *buf,
                             size_t len, int sent)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    struct socket_client_init_t *p = &c->client_init;

    if (p->cb.on_sent) {
        p->cb.on_sent(p->cb.param, buf, len, sent, &conn->clih);
    }
}

static void callback_on_closed(struct notification_conn_t *conn,
                               const char *err)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    struct socket_client_init_t *p = &c->client_init;

    if (p->cb.on_closed) {
        p->cb.on_closed(p->cb.param, err, &conn->clih);
    }
}

static void release_notification_data(struct notification_data_t *msg)
{
#ifdef ENABLE_DATA_SERIAL
// LOGV("release data serial: %lld", (long long)msg->serial);
#endif
    if (h2o_linklist_is_linked(&msg->cmn.super.link)) {
        h2o_linklist_unlink(&msg->cmn.super.link);
    }
    free(msg);
}

static void release_data_linkedlist(struct notification_conn_t *conn,
                                    h2o_linklist_t *messages, int sent)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;

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
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;

    /**
     * link to sending list and send
     */
    h2o_linklist_insert(&conn->sending, &data->cmn.super.link);

    if (c->client_init.io_timeout > 0) {
        /* I/O timeout */
        conn->_timeout.cb = write_timeout_cb;
        h2o_timer_link(c->loop, c->client_init.io_timeout, &conn->_timeout);
    }

    h2o_socket_write(conn->sock, &data->data, 1, on_write);
}

static void write_pending(struct notification_conn_t *conn)
{
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
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
    LOGV("release serial: %u", conn->clih.serial);
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

static void on_error(struct notification_conn_t *conn, const char *prefix,
                     const char *err)
{
    struct libh2o_socket_client_ctx_t *c;
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

static void conn_timeout_cb(h2o_timer_t *entry)
{
    struct notification_conn_t *conn;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, _timeout, entry);
    h2o_timer_unlink(&conn->_timeout);
    on_error(conn, "conn_timeout_cb", "Connect timeout");
}

static void on_read(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn = sock->data;

    if (err != NULL) {
        /* read failed */
        on_error(conn, "read failed", err);
        return;
    }

    callback_on_data(conn, sock->input->bytes, sock->input->size);
    h2o_buffer_consume(&sock->input, sock->input->size);

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "user close", "NO error");
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
        on_error(conn, "write failed", err);
        return;
    }

    release_sending(conn);

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "user close", "NO error");
        return;
    }

    write_pending(conn);
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn = sock->data;

    if (err != NULL) {
        /* TLS handshake failed */
        on_error(conn, "TLS handshake failure", err);
        return;
    }

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "user close", "NO error");
        return;
    }

    callback_on_connected(conn);
    h2o_socket_read_start(sock, on_read);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct notification_conn_t *conn = sock->data;
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;

    /* unlink 'connect timeout' */
    if (h2o_timer_is_linked(&conn->_timeout)) {
        h2o_timer_unlink(&conn->_timeout);
    }

    if (err != NULL) {
        /* connection failed */
        on_error(conn, "failed to connect to host", err);
        return;
    }

    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "user close", "NO error");
        return;
    }

    if (c->ssl_ctx != NULL) {
        const char *host = conn->req.host;
        if (conn->req.alias_host) {
            host = conn->req.alias_host;
        }
        h2o_socket_ssl_handshake(sock, c->ssl_ctx, host,
                                 h2o_iovec_init(NULL, 0),
                                 on_handshake_complete);
    } else {
        callback_on_connected(conn);
        h2o_socket_read_start(sock, on_read);
    }
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *err,
                       struct addrinfo *res, void *_conn)
{
    struct notification_conn_t *conn = (struct notification_conn_t *)_conn;
    struct libh2o_socket_client_ctx_t *c = conn->cmn.c;
    h2o_socket_t *sock;
    struct addrinfo *selected;

    if (err != NULL) {
        /* resolve host failed */
        on_error(conn, "failed to resolve host", err);
        return;
    }
    if (conn->cmn.cmd == NOTIFICATION_CLOSE) {
        on_error(conn, "user close", "NO error");
        return;
    }

    selected = h2o_hostinfo_select_one(res);
    sock = h2o_socket_connect(c->loop, selected->ai_addr, selected->ai_addrlen,
                              on_connect);
    if (sock == NULL) {
        /* create socket failed */
        on_error(conn, "failed to create socket", strerror(errno));
        return;
    }
    sock->data = conn;
    conn->sock = sock;
    callback_on_host_resolved(conn, selected);
    return;
}

static int foreach_conn(struct libh2o_socket_client_ctx_t *c,
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

static void release_conn_linkedlist(struct libh2o_socket_client_ctx_t *c,
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

static void release_conns(struct libh2o_socket_client_ctx_t *c, const char *err)
{
    release_conn_linkedlist(c, &c->conns, err);
}

static void on_notification(h2o_multithread_receiver_t *receiver,
                            h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_cmn_t *cmn = (struct notification_cmn_t *)msg;
        struct libh2o_socket_client_ctx_t *c = cmn->c;

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
        } else if (cmn->cmd == NOTIFICATION_CONN) {
            struct notification_conn_t *conn =
                (struct notification_conn_t *)cmn;
            h2o_iovec_t iov_name =
                h2o_iovec_init(conn->req.host, strlen(conn->req.host));
            h2o_iovec_t iov_serv =
                h2o_iovec_init(conn->req.port, strlen(conn->req.port));

            h2o_linklist_insert(&c->conns, &msg->link);

            if (conn->req.conn_timeout > 0) {
                /* connect timeout */
                conn->_timeout.cb = conn_timeout_cb;
                h2o_timer_link(c->loop, conn->req.conn_timeout,
                               &conn->_timeout);
            }

            /* resolve host name */
            h2o_hostinfo_getaddr(&c->getaddr_receiver, iov_name, iov_serv,
                                 AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                                 AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr,
                                 conn);

        } else if (cmn->cmd == NOTIFICATION_CLOSE) {
            struct notification_data_t *data =
                (struct notification_data_t *)cmn;
            struct notification_conn_t *conn = data->conn;
            conn->cmn.cmd = NOTIFICATION_CLOSE;
            if (conn->sock == NULL) {
                LOGW("caller want to close without connection");
            } else if (!h2o_socket_is_writing(conn->sock)) {
                on_error(conn, "user close", "NO error");
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
    struct libh2o_socket_client_ctx_t *c = u;

    if (c->client_init.ssl_init.passwd_cb) {
        return c->client_init.ssl_init.passwd_cb(buf, size, rwflag,
                                                 c->client_init.cb.param);
    }
    ASSERT(0);
    return 0;
}

static void init_openssl(struct libh2o_socket_client_ctx_t *c)
{
    if (c->client_init.ssl_init.cert_file) {
        static int openssl_inited = 0;
        int rc;

        if (openssl_inited++ == 0) {
            SSL_load_error_strings();
            SSL_library_init();
            OpenSSL_add_all_algorithms();
        }

        c->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
        SSL_CTX_load_verify_locations(c->ssl_ctx,
                                      c->client_init.ssl_init.cert_file, NULL);
        SSL_CTX_set_verify(c->ssl_ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);

        if (c->client_init.ssl_init.cli_cert_file) {
            int type = SSL_FILETYPE_PEM;
            const char *p = strchr(c->client_init.ssl_init.cli_cert_file, '.');
            if (p != NULL) {
                if (strncasecmp(p + 1, "der", 3) == 0) {
                    type = SSL_FILETYPE_ASN1;
                }
            }
            rc = SSL_CTX_use_certificate_file(
                c->ssl_ctx, c->client_init.ssl_init.cli_cert_file, type);
            ASSERT(rc > 0);
            if (rc <= 0) {
                LOGW("Error setting the certificate file");
                goto ERROR;
            }
        }
        if (c->client_init.ssl_init.cli_key_file) {
            int type = SSL_FILETYPE_PEM;
            const char *p = strchr(c->client_init.ssl_init.cli_key_file, '.');
            if (p != NULL) {
                if (strncasecmp(p + 1, "der", 3) == 0) {
                    type = SSL_FILETYPE_ASN1;
                }
            }
            SSL_CTX_set_default_passwd_cb(c->ssl_ctx, cli_key_file_passwd_cb);
            SSL_CTX_set_default_passwd_cb_userdata(c->ssl_ctx, c);
            rc = SSL_CTX_use_PrivateKey_file(
                c->ssl_ctx, c->client_init.ssl_init.cli_key_file, type);
            ASSERT(rc > 0);
            if (rc <= 0) {
                LOGW("Error setting the key file");
                goto ERROR;
            }

            /* Make sure the key and certificate file match */
            rc = SSL_CTX_check_private_key(c->ssl_ctx);
            ASSERT(rc > 0);
            if (rc <= 0) {
                LOGW("Private key does not match the certificate public key");
                goto ERROR;
            }
        }
    }

    return;

ERROR:
    c->exit_loop = 1;
    return;
}

static void release_openssl(struct libh2o_socket_client_ctx_t *c)
{
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
    }
}

static void *client_loop(void *arg)
{
    struct libh2o_socket_client_ctx_t *c = arg;

    init_openssl(c);

    while (!c->exit_loop) {
        h2o_evloop_run(c->loop, INT32_MAX);
    }

    while (!h2o_linklist_is_empty(&c->conns)) {
        h2o_evloop_run(c->loop, DISPOSE_TIMEOUT_MS);
    }

    ASSERT(h2o_linklist_is_empty(&c->conns));
    release_conns(c, "event loop quiting");
    release_openssl(c);

    /**
     * this will clean thread local data used by pool
     */
    h2o_cleanup_thread();
    return 0;
}

const char *libh2o_socket_client_get_version(void) { return H2O_VERSION; }

struct libh2o_socket_client_ctx_t *
libh2o_socket_client_start(const struct socket_client_init_t *client_init)
{
    struct libh2o_socket_client_ctx_t *c;

    if (!client_init) return NULL;

    if (client_init->ssl_init.cli_cert_file &&
        !client_init->ssl_init.cli_key_file) {
        LOGW("missing client key file");
        return NULL;
    }

    if (client_init->ssl_init.cli_key_file &&
        !client_init->ssl_init.cli_cert_file) {
        LOGW("missing client certificate file");
        return NULL;
    }

    if (client_init->ssl_init.cli_cert_file ||
        client_init->ssl_init.cli_key_file) {
        if (!client_init->ssl_init.cert_file) {
            LOGW("missing server certificate file");
            return NULL;
        }
    }

    c = h2o_mem_alloc(sizeof(*c));
    if (c) {
        memset(c, 0x00, sizeof(*c));
        c->loop = h2o_evloop_create();
        h2o_linklist_init_anchor(&c->conns);

        c->queue = h2o_multithread_create_queue(c->loop);
        h2o_multithread_register_receiver(c->queue, &c->getaddr_receiver,
                                          h2o_hostinfo_getaddr_receiver);
        h2o_multithread_register_receiver(c->queue, &c->notifications,
                                          on_notification);
        memcpy(&c->client_init, client_init, sizeof(*client_init));

        h2o_multithread_create_thread(&c->tid, NULL, client_loop, (void *)c);
    }

    return c;
}

void libh2o_socket_client_stop(struct libh2o_socket_client_ctx_t *c)
{
    if (!c) return;

    notify_thread_quit(c);
    pthread_join(c->tid, NULL);
    if (c->queue) {
        h2o_multithread_unregister_receiver(c->queue, &c->getaddr_receiver);
        h2o_multithread_unregister_receiver(c->queue, &c->notifications);
        h2o_multithread_destroy_queue(c->queue);
    }
    if (c->loop != NULL) {
        h2o_evloop_destroy(c->loop);
    }
    free(c);
}

const struct socket_client_handle_t *
libh2o_socket_client_req(struct libh2o_socket_client_ctx_t *c,
                         const struct socket_client_req_t *req)
{
    struct notification_conn_t *conn;

    if (c == NULL || req == NULL) return NULL;

    if (req->host == NULL || req->port == NULL) {
        return NULL;
    }
    conn = notify_thread_connect(c, req);
    return &conn->clih;
}

size_t libh2o_socket_client_send(const struct socket_client_handle_t *clih,
                                 const void *buf, size_t len)
{
    struct notification_conn_t *conn;

    if (clih == NULL) return 0;
    if (buf == NULL || len == 0) return 0;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);

    notify_thread_data(conn, buf, len);
    return len;
}

void libh2o_socket_client_release(const struct socket_client_handle_t *clih)
{
    struct notification_conn_t *conn;

    if (clih == NULL) return;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);

    notify_thread_release(conn);
}

#ifdef LIBH2O_UNIT_TEST
#include <signal.h>

#define SOCKET_CLIENT_STATE_HOSTRESOLVED 0x01
#define SOCKET_CLIENT_STATE_CONNECTED 0x02
#define SOCKET_CLIENT_STATE_CLOSED 0xFFFFFFFF
struct socket_client_state_t {
    const struct socket_client_handle_t *clih;
    int32_t state;
};

struct sock_clients_t {
    struct libh2o_socket_client_ctx_t *c;
    int nclients;
    struct socket_client_state_t *clients;
};

struct sock_clients_t sock_clients;

static void
cb_socket_client_on_host_resolved(void *param, struct addrinfo *addr,
                                  const struct socket_client_handle_t *clih)
{
    struct sock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                SOCKET_CLIENT_STATE_HOSTRESOLVED);
        }
    }
}

static void
cb_socket_client_on_connected(void *param,
                              const struct socket_client_handle_t *clih)
{
    LOGV("%s() @line: %d clih: %p", __FUNCTION__, __LINE__, clih);
    struct sock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                SOCKET_CLIENT_STATE_CONNECTED);
        }
    }
}

static void cb_socket_client_on_data(void *param, void *buf, size_t len,
                                     const struct socket_client_handle_t *clih)
{
    struct sock_clients_t *clients = param;
    (void)clients;
    fwrite(buf, 1, len, stdout);
}

static void cb_socket_client_on_sent(void *param, void *buf, size_t len,
                                     int sent,
                                     const struct socket_client_handle_t *clih)
{
    struct sock_clients_t *clients = param;
    (void)clients;
    free(buf);
}

static void
cb_socket_client_on_closed(void *param, const char *err,
                           const struct socket_client_handle_t *clih)
{
    LOGV("%s() @line: %d clih: %p", __FUNCTION__, __LINE__, clih);
    struct sock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                SOCKET_CLIENT_STATE_CLOSED);
        }
    }
}

int main(int argc, char **argv)
{
    /**
     * test with 'nc -l 1234'
     */
    struct sock_clients_t clients;
    int running = 1;

    signal(SIGPIPE, SIG_IGN);

    /**
     * client init param
     */
    struct socket_client_init_t client_init;
    memset(&client_init, 0x00, sizeof(client_init));

    client_init.io_timeout = 10000;
    client_init.cb.on_host_resolved = cb_socket_client_on_host_resolved;
    client_init.cb.on_connected = cb_socket_client_on_connected;
    client_init.cb.on_data = cb_socket_client_on_data;
    client_init.cb.on_sent = cb_socket_client_on_sent;
    client_init.cb.on_closed = cb_socket_client_on_closed;
    client_init.cb.param = &clients;

    /**
     * 1: create socket client context
     * event loop thread will be created
     */
    clients.c = libh2o_socket_client_start(&client_init);

    clients.nclients = argc;
    clients.clients = malloc(sizeof(struct socket_client_state_t) * argc);
    memset(clients.clients, 0x00, sizeof(struct socket_client_state_t) * argc);

    /**
     * 2: create socket client request
     * on_host_resolved and on connected will be called back
     */
    struct socket_client_req_t req = {"127.0.0.1", "1234"};
    clients.clients[0].clih = libh2o_socket_client_req(clients.c, &req);

    int i;
    for (i = 1; i < argc; ++i) {
        req.host = argv[i];
        clients.clients[i].clih = libh2o_socket_client_req(clients.c, &req);
    }

    h2o_srand();
    while (running) {
        struct socket_client_state_t *cli;
        int state;

        i = h2o_rand() % clients.nclients;
        cli = clients.clients + i;

        state = __sync_fetch_and_or(&cli->state, 0);
        if (state > SOCKET_CLIENT_STATE_CONNECTED && cli->clih) {
            for (int i = 0; i < 10; ++i) {
                const char *p = "hello server\n";
                const char *buf = strdup(p);
                /**
                 * 3: send data for this connection
                 * on_sent will be called back
                 */
                libh2o_socket_client_send(cli->clih, buf, strlen(buf) + 1);
            }
            if (0) {
                usleep(1000000);
                libh2o_socket_client_release(cli->clih);
            }
        } else if (state < 0) {
            /**
             * closed by peer
             */
            cli->clih = NULL;
        }

        /* check all client alive */
        for (i = 0; i < clients.nclients; ++i) {
            if (clients.clients[i].clih) {
                break;
            }
        }
        if (i == clients.nclients) {
            running = 0;
            continue;
        }
        usleep(1000);
    }
    libh2o_socket_client_stop(clients.c);

    free(clients.clients);
    return 0;
}
#endif
