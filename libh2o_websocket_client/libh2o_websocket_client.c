/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
*   FILE NAME   : libh2o_websocket_client.c
*   CREATE DATE : 2018-12-10
*   MODULE      : libh2o_websocket_client
*   AUTHOR      : chenbd
*---------------------------------------------------------------------------*
*   MEMO        :
*****************************************************************************/

/****************************************************************************
*                       Include File Section                                *
*****************************************************************************/
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "h2o.h"
#include "h2o/websocketclient.h"

#include "libh2o_websocket_client.h"

/****************************************************************************
*                       Macro Definition Section                            *
*****************************************************************************/
#define DEBUG_SERIAL 1

#define NOTIFICATION_CONN 0
#define NOTIFICATION_DATA 1
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
 * websocket client context type
 */
struct libh2o_websocket_client_ctx_t {
    pthread_t tid;            /* event loop thread id */
    h2o_httpclient_ctx_t ctx; /* http client context */
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t notifications;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_linklist_t conns;
    struct websocket_client_init_t client_init;
    h2o_httpclient_connection_pool_t *connpool;
    uint64_t websocket_timeout;
    h2o_socketpool_t *sockpool;
    SSL_CTX *ssl_ctx;
    uint32_t serial_counter;
    int exit_loop;
    int chunk_size;
};

/**
 * MUST the first member for sub struct
 */
struct notification_cmn_t {
    h2o_multithread_message_t
        super; /* used to call h2o_multithread_send_message() */
    struct libh2o_websocket_client_ctx_t *c;
    uint32_t cmd;
};

struct notification_quit_t {
    struct notification_cmn_t cmn;
};

struct notification_conn_t {
    struct notification_cmn_t cmn;
    h2o_httpclient_t *client; /* currently not used */
    h2o_websocket_client_conn_t *wsconn;
    char *sec_websock_key;
    h2o_linklist_t pending; /* list for pending data sent */
    h2o_timer_t dispose_timeout;
#ifdef ENABLE_DATA_SERIAL
    uint32_t serial_counter;
#endif
    int fd; /* for nonce */
    h2o_url_t url_parsed;
    struct websocket_client_req_t req;
    h2o_mem_pool_t pool;
    struct websocket_client_handle_t clih;
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
static h2o_httpclient_head_cb
on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *method,
           h2o_url_t *url, const h2o_header_t **headers, size_t *num_headers,
           h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
           h2o_httpclient_properties_t *props, h2o_url_t *origin);
static h2o_httpclient_body_cb on_head(h2o_httpclient_t *client,
                                      const char *errstr, int version,
                                      int status, h2o_iovec_t msg,
                                      h2o_header_t *headers, size_t num_headers,
                                      int header_requires_dup);

static void on_error(struct notification_conn_t *conn, const char *prefix,
                     const char *err);

static void callback_on_sent(struct notification_conn_t *conn, void *buf,
                             size_t len, int sent);

static void callback_on_closed(struct notification_conn_t *conn,
                               const char *err);

/****************************************************************************
*                       Functions Implement Section                         *
*****************************************************************************/
static void notify_thread_quit(struct libh2o_websocket_client_ctx_t *c)
{
    struct notification_quit_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_QUIT;
    msg->cmn.c = c;

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
}

static void dup_req(struct websocket_client_req_t *dst,
                    const struct websocket_client_req_t *src)
{
    dst->url = strdup(src->url);
    dst->opcode = src->opcode;
}

static void free_req(struct websocket_client_req_t *req)
{
    ASSERT(req->url);
    free(req->url);
}

static struct notification_conn_t *
notify_thread_connect(struct libh2o_websocket_client_ctx_t *c,
                      const struct websocket_client_req_t *req)
{
    struct notification_conn_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_CONN;
    msg->cmn.c = c;

    h2o_linklist_init_anchor(&msg->pending);

    msg->clih.serial = __sync_fetch_and_add(&c->serial_counter, 1);
#ifdef DEBUG_SERIAL
    LOGV("create serial: %u", msg->clih.serial);
#endif

    dup_req(&msg->req, req);

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
#ifdef ENABLE_DATA_SERIAL
    msg->serial = (uint64_t)conn->clih.serial << 32 |
                  __sync_fetch_and_add(&conn->serial_counter, 1);
// LOGV("create data serial: %lld", (long long)msg->serial);
#endif

    h2o_multithread_send_message(&msg->cmn.c->notifications, &msg->cmn.super);
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

static void release_pending_data_linklist(struct notification_conn_t *conn,
                                          int sent)
{
    h2o_linklist_t *messages = &conn->pending;
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;

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

static void release_notification_conn(struct notification_conn_t *conn)
{
#ifdef DEBUG_SERIAL
    LOGV("release serial: %u", conn->clih.serial);
#endif
    if (h2o_timer_is_linked(&conn->dispose_timeout)) {
        h2o_timer_unlink(&conn->dispose_timeout);
    }
    /* unlink from 'conns' */
    if (h2o_linklist_is_linked(&conn->cmn.super.link)) {
        h2o_linklist_unlink(&conn->cmn.super.link);
    }

    release_pending_data_linklist(conn, 0);

    /* release h2o websocket client conn */
    if (conn->wsconn) {
        h2o_websocket_client_close(conn->wsconn);
        conn->wsconn = NULL;
    }

    if (conn->fd > 0) close(conn->fd);
    free_req(&conn->req);
    h2o_mem_clear_pool(&conn->pool);
    free(conn);
}

static void queue_websocket_data(struct notification_conn_t *conn,
                                 struct notification_data_t *data)
{
    struct wslay_event_msg msgarg = {
        conn->req.opcode, (const uint8_t *)data->data.base, data->data.len};
    ASSERT(conn == data->conn);
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static void queue_websocket_close(struct notification_conn_t *conn)
{
    struct wslay_event_msg msgarg = {WSLAY_CONNECTION_CLOSE, NULL, 0};
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static void queue_websocket_ping(struct notification_conn_t *conn)
{
    struct wslay_event_msg msgarg = {WSLAY_PING, NULL, 0};
    wslay_event_queue_msg(conn->wsconn->ws_ctx, &msgarg);
}

static void flush_pending_data_linklist(struct notification_conn_t *conn)
{
    h2o_linklist_t *messages = &conn->pending;
    struct libh2o_websocket_client_ctx_t *c;
    c = conn->cmn.c;

    ASSERT(conn->wsconn != NULL);
    if (conn->wsconn == NULL) return;

    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_data_t *data = (struct notification_data_t *)msg;
        ASSERT(c == data->cmn.c);
        ASSERT(NOTIFICATION_DATA == data->cmn.cmd);
        h2o_linklist_unlink(&msg->link);

        queue_websocket_data(conn, data);
        h2o_websocket_client_proceed(conn->wsconn);
        callback_on_sent(conn, data->data.base, data->data.len, 1);
        release_notification_data(data);
    }
}

static int foreach_conn(struct libh2o_websocket_client_ctx_t *c,
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

static int queue_websocket_close_cb(struct notification_conn_t *conn,
                                    void *cbdata)
{
    if (conn->wsconn != NULL) {
        queue_websocket_close(conn);
        h2o_websocket_client_proceed(conn->wsconn);
    }
    return 0;
}

static void on_notification(h2o_multithread_receiver_t *receiver,
                            h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_cmn_t *cmn = (struct notification_cmn_t *)msg;
        struct libh2o_websocket_client_ctx_t *c = cmn->c;

        h2o_linklist_unlink(&msg->link);
        if (cmn->cmd == NOTIFICATION_DATA) {
            struct notification_data_t *data =
                (struct notification_data_t *)cmn;
            struct notification_conn_t *conn = data->conn;
            if (conn->wsconn != NULL) {
                queue_websocket_data(conn, data);
                h2o_websocket_client_proceed(conn->wsconn);
                callback_on_sent(conn, data->data.base, data->data.len, 1);
                release_notification_data(data);
            } else {
                LOGW("caller want to send data without connection");
                h2o_linklist_insert(&conn->pending, &msg->link);
            }
        } else if (cmn->cmd == NOTIFICATION_CONN) {
            struct notification_conn_t *conn =
                (struct notification_conn_t *)cmn;
            h2o_mem_init_pool(&conn->pool);
            /* parse URL */
            if (h2o_url_parse(conn->req.url, SIZE_MAX, &conn->url_parsed) !=
                0) {
                LOGW("unrecognized type of URL: %s", conn->req.url);
                on_error(conn, "on_notification", "URL error");
                continue;
            }
            h2o_linklist_insert(&c->conns, &msg->link);
            h2o_httpclient_connect(&conn->client, &conn->pool, conn,
                                   &conn->cmn.c->ctx, conn->cmn.c->connpool,
                                   &conn->url_parsed, on_connect);
        } else if (cmn->cmd == NOTIFICATION_QUIT) {
            foreach_conn(c, queue_websocket_close_cb, NULL);
            c->exit_loop = 1;
            free(msg);
        } else {
            ASSERT(0);
            free(msg);
        }
    }
}

static void callback_on_connected(struct notification_conn_t *conn)
{
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;
    struct websocket_client_init_t *p = &c->client_init;

    if (p->cb.on_connected) {
        p->cb.on_connected(p->cb.param, &conn->clih);
    }
}

static void callback_on_handshaked(struct notification_conn_t *conn)
{
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;
    struct websocket_client_init_t *p = &c->client_init;

    if (p->cb.on_handshaked) {
        p->cb.on_handshaked(p->cb.param, &conn->clih);
    }
}

static void callback_on_sent(struct notification_conn_t *conn, void *buf,
                             size_t len, int sent)
{
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;
    struct websocket_client_init_t *p = &c->client_init;

    if (p->cb.on_sent) {
        p->cb.on_sent(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_recv(struct notification_conn_t *conn, void *buf,
                             size_t len)
{
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;
    struct websocket_client_init_t *p = &c->client_init;

    if (p->cb.on_recv) {
        p->cb.on_recv(p->cb.param, buf, len, &conn->clih);
    }
}

static void callback_on_closed(struct notification_conn_t *conn,
                               const char *err)
{
    struct libh2o_websocket_client_ctx_t *c = conn->cmn.c;
    struct websocket_client_init_t *p = &c->client_init;

    if (p->cb.on_closed) {
        p->cb.on_closed(p->cb.param, err, &conn->clih);
    }
}

static void release_conn_linkedlist(struct libh2o_websocket_client_ctx_t *c,
                                    h2o_linklist_t *messages, const char *err)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_conn_t *conn = (struct notification_conn_t *)msg;
        ASSERT(c == conn->cmn.c);
        ASSERT(NOTIFICATION_CONN == conn->cmn.cmd);
        h2o_linklist_unlink(&msg->link);

        callback_on_closed(conn, err);
        release_notification_conn(conn);
    }
}

static void release_conns(struct libh2o_websocket_client_ctx_t *c,
                          const char *err)
{
    release_conn_linkedlist(c, &c->conns, err);
}

static void dispose_timeout_cb(h2o_timer_t *entry)
{
    struct notification_conn_t *conn;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, dispose_timeout,
                                  entry);
    release_notification_conn(conn);
}

static void on_error(struct notification_conn_t *conn, const char *prefix,
                     const char *err)
{
    struct libh2o_websocket_client_ctx_t *c;
    ASSERT(err != NULL);
    LOGW("%s:%s", prefix, err);
    callback_on_closed(conn, err);
    if (conn->wsconn) {
        h2o_websocket_client_close(conn->wsconn);
        conn->wsconn = NULL;
    }

    c = conn->cmn.c;
    conn->dispose_timeout.cb = dispose_timeout_cb;
    h2o_timer_link(c->ctx.loop, DISPOSE_TIMEOUT_MS, &conn->dispose_timeout);
}

static void on_ws_message(h2o_websocket_client_conn_t *_conn,
                          const struct wslay_event_on_msg_recv_arg *arg)
{
    struct notification_conn_t *conn = _conn->data;
    if (arg == NULL) {
        on_error(conn, "on_ws_message", "NULL");
        return;
    }

    // LOGV("on_ws_message() opcode: %d", arg->opcode);
    if (!wslay_is_ctrl_frame(arg->opcode)) {
        callback_on_recv(conn, (void *)arg->msg, arg->msg_length);
    }
}

h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr,
                               int version, int status, h2o_iovec_t msg,
                               h2o_header_t *headers, size_t num_headers,
                               int header_requires_dup)
{
    struct notification_conn_t *conn = client->data;

    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        on_error(conn, "on_head error", errstr);
        return NULL;
    }

#if 0
    size_t i;
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    printf("HTTP/%d", (version >> 8));
    if ((version & 0xff) != 0) {
        printf(".%d", version & 0xff);
    }
    printf(" %d", status);
    if (msg.len == 0) {
        printf(" %.*s\n", (int)msg.len, msg.base);
    } else {
        printf("\n");
    }
    for (i = 0; i != num_headers; ++i)
        printf("%.*s: %.*s\n", (int)headers[i].name->len, headers[i].name->base, (int)headers[i].value.len, headers[i].value.base);
    printf("\n");
#endif

    if (0 != h2o_is_websocket_respheader(version, status, conn->sec_websock_key,
                                         headers, num_headers)) {
        LOGE("No websocket response header");
        on_error(conn, "on_head error", "No websocket response header");
        return NULL;
    }
    conn->wsconn = h2o_upgrade_to_websocket_client(client, conn, version,
                                                   conn->fd, on_ws_message);
    conn->client = NULL;
    callback_on_handshaked(conn);

    /** It's safe to clear memory pool now */
    h2o_mem_clear_pool(&conn->pool);

    /**
     * flush pending data in link list
     */
    flush_pending_data_linklist(conn);

    return NULL;
}

h2o_httpclient_head_cb
on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *_method,
           h2o_url_t *url, const h2o_header_t **headers, size_t *num_headers,
           h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
           h2o_httpclient_properties_t *props, h2o_url_t *origin)
{
    h2o_header_t *_headers;
    const h2o_url_t *url_parsed;

    struct notification_conn_t *conn = client->data;
    if (errstr != NULL) {
        on_error(conn, "connect error", errstr);
        return NULL;
    }

    callback_on_connected(conn);
    conn->fd = open("/dev/urandom", O_RDONLY);
    url_parsed = &conn->url_parsed;
    *_method = h2o_iovec_init(H2O_STRLIT("GET"));
    *url = conn->url_parsed;
    *num_headers = h2o_websocket_client_create_headers(
        &conn->pool, url_parsed, conn->fd, &_headers, &conn->sec_websock_key);
    ASSERT(*num_headers > 0);
    ASSERT(_headers != NULL);
#if 0
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    LOGV("method: %s", _method->base);
    size_t i;

    for (i = 0; i != *num_headers; ++i)
        printf("%.*s: %.*s\n", (int)_headers[i].name->len, _headers[i].name->base, (int)_headers[i].value.len,
               _headers[i].value.base);
    printf("\n");
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
#endif
    *headers = _headers;
    *body = h2o_iovec_init(NULL, 0);

    return on_head;
}

static int cli_key_file_passwd_cb(char *buf, int size, int rwflag, void *u)
{
    struct libh2o_websocket_client_ctx_t *c = u;

    if (c->client_init.ssl_init.passwd_cb) {
        return c->client_init.ssl_init.passwd_cb(buf, size, rwflag,
                                                 c->client_init.cb.param);
    }
    ASSERT(0);
    return 0;
}

static void init_openssl(struct libh2o_websocket_client_ctx_t *c)
{
    if (c->client_init.ssl_init.cert_file) {
        static int openssl_inited = 0;
        int rc;

        if (openssl_inited++ == 0) {
            SSL_load_error_strings();
            SSL_library_init();
            OpenSSL_add_all_algorithms();
        }

        c->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
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

static void release_openssl(struct libh2o_websocket_client_ctx_t *c)
{
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
    }
}
static void init_conn_poll(struct libh2o_websocket_client_ctx_t *c)
{
    h2o_httpclient_connection_pool_t *connpool;
    h2o_socketpool_t *sockpool;

    connpool = h2o_mem_alloc(sizeof(*connpool));
    sockpool = h2o_mem_alloc(sizeof(*sockpool));
    h2o_socketpool_init_global(sockpool, 128);
    h2o_socketpool_set_timeout(sockpool,
                               c->client_init.io_timeout + 10000 /* in msec */);
    h2o_socketpool_register_loop(sockpool, c->ctx.loop);
    h2o_httpclient_connection_pool_init(connpool, sockpool);
    c->connpool = connpool;
    c->sockpool = sockpool;
}

static void release_conn_poll(struct libh2o_websocket_client_ctx_t *c)
{
    h2o_socketpool_dispose(c->sockpool);
    free(c->sockpool);
    free(c->connpool);
}

static void *client_loop(void *arg)
{
    struct libh2o_websocket_client_ctx_t *c = arg;

    init_openssl(c);
    init_conn_poll(c);
    h2o_socketpool_set_ssl_ctx(c->sockpool, c->ssl_ctx);

    while (!c->exit_loop) {
        h2o_evloop_run(c->ctx.loop, INT32_MAX);
    }

    while (!h2o_linklist_is_empty(&c->conns)) {
        h2o_evloop_run(c->ctx.loop, DISPOSE_TIMEOUT_MS);
    }

    ASSERT(h2o_linklist_is_empty(&c->conns));
    release_conns(c, "event loop quiting");

    release_conn_poll(c);
    release_openssl(c);

    /**
     * this will clean thread local data used by pool
     */
    h2o_cleanup_thread();
    return 0;
}

const char *libh2o_websocket_client_get_version(void) { return H2O_VERSION; }

struct libh2o_websocket_client_ctx_t *
libh2o_websocket_client_start(const struct websocket_client_init_t *client_init)
{
    struct libh2o_websocket_client_ctx_t *c;

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
        c->ctx.loop = h2o_evloop_create();
        h2o_linklist_init_anchor(&c->conns);
        c->chunk_size = 1024;
        c->websocket_timeout = client_init->io_timeout;

        /**
         * init http client context
         */
        c->ctx.getaddr_receiver = &c->getaddr_receiver;
        c->ctx.io_timeout = client_init->io_timeout;
        c->ctx.connect_timeout = client_init->io_timeout;
        c->ctx.first_byte_timeout = client_init->io_timeout;
        c->ctx.websocket_timeout = &c->websocket_timeout;
        c->ctx.keepalive_timeout = client_init->io_timeout + 15000;
        c->ctx.max_buffer_size = 0;
        memset(&c->ctx.http2, 0x00, sizeof(c->ctx.http2));

        c->queue = h2o_multithread_create_queue(c->ctx.loop);
        h2o_multithread_register_receiver(c->queue, &c->getaddr_receiver,
                                          h2o_hostinfo_getaddr_receiver);
        h2o_multithread_register_receiver(c->queue, &c->notifications,
                                          on_notification);
        memcpy(&c->client_init, client_init, sizeof(*client_init));

        h2o_multithread_create_thread(&c->tid, NULL, client_loop, (void *)c);
    }

    return c;
}

void libh2o_websocket_client_stop(struct libh2o_websocket_client_ctx_t *c)
{
    notify_thread_quit(c);
    pthread_join(c->tid, NULL);
    if (c->queue) {
        h2o_multithread_unregister_receiver(c->queue, &c->getaddr_receiver);
        h2o_multithread_unregister_receiver(c->queue, &c->notifications);
        h2o_multithread_destroy_queue(c->queue);
    }
    if (c->ctx.loop != NULL) {
        h2o_evloop_destroy(c->ctx.loop);
    }
    free(c);
}

const struct websocket_client_handle_t *
libh2o_websocket_client_req(struct libh2o_websocket_client_ctx_t *c,
                            const struct websocket_client_req_t *req)
{
    struct notification_conn_t *conn;

    if (c == NULL || req == NULL || req->url == NULL) return NULL;

    if (req->opcode != WSLAY_TEXT_FRAME && req->opcode != WSLAY_BINARY_FRAME) {
        return NULL;
    }
    conn = notify_thread_connect(c, req);
    return &conn->clih;
}

size_t
libh2o_websocket_client_send(const struct websocket_client_handle_t *clih,
                             const void *buf, size_t len)
{
    struct notification_conn_t *conn;

    if (clih == NULL) return 0;
    if (buf == NULL || len == 0) return 0;

    conn = H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);

    notify_thread_data(conn, buf, len);
    return len;
}

#ifdef LIBH2O_UNIT_TEST
#include <signal.h>

#define WEBSOCKET_CLIENT_STATE_CONNECTED 0x01
#define WEBSOCKET_CLIENT_STATE_HANDSHAKED 0x02
#define WEBSOCKET_CLIENT_STATE_CLOSED 0xFFFFFFFF
struct websocket_client_state_t {
    const struct websocket_client_handle_t *clih;
    int32_t state;
};

struct websock_clients_t {
    struct libh2o_websocket_client_ctx_t *c;
    int nclients;
    struct websocket_client_state_t *clients;
};

struct websock_clients_t sock_clients;

static void
cb_websocket_client_on_connected(void *param,
                                 const struct websocket_client_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    struct websock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                WEBSOCKET_CLIENT_STATE_CONNECTED);
        }
    }
}

static void
cb_websocket_client_on_handshaked(void *param,
                                  const struct websocket_client_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    struct websock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                WEBSOCKET_CLIENT_STATE_HANDSHAKED);
        }
    }
}

static void
cb_websocket_client_on_sent(void *param, void *buf, size_t len,
                            const struct websocket_client_handle_t *clih)
{
    struct websock_clients_t *clients = param;
    (void)clients;
    free(buf);
}

static void
cb_websocket_client_on_recv(void *param, void *buf, size_t len,
                            const struct websocket_client_handle_t *clih)
{
    struct websock_clients_t *clients = param;
    (void)clients;
    // fwrite(buf, 1, len, stdout);
}

static void
cb_websocket_client_on_closed(void *param, const char *err,
                              const struct websocket_client_handle_t *clih)
{
    LOGV("%s() @line: %d err: %s", __FUNCTION__, __LINE__, err ? err : "");
    struct websock_clients_t *clients = param;
    int i;
    for (i = 0; i < clients->nclients; ++i) {
        if (clients->clients[i].clih == clih) {
            __sync_fetch_and_or(&clients->clients[i].state,
                                WEBSOCKET_CLIENT_STATE_CLOSED);
        }
    }
}

int main(int argc, char **argv)
{
    /**
     * tested with 'examples-websocket-evloop'
     */
    struct websock_clients_t clients;
    int running = 1;

    signal(SIGPIPE, SIG_IGN);

    /**
     * client init param
     */
    struct websocket_client_init_t client_init;
    memset(&client_init, 0x00, sizeof(client_init));

    client_init.io_timeout = 10000; /* 10 sec */
    client_init.cb.on_connected = cb_websocket_client_on_connected;
    client_init.cb.on_handshaked = cb_websocket_client_on_handshaked;
    client_init.cb.on_sent = cb_websocket_client_on_sent;
    client_init.cb.on_recv = cb_websocket_client_on_recv;
    client_init.cb.on_closed = cb_websocket_client_on_closed;
    client_init.cb.param = &clients;

    /**
     * 1: create websocket client context
     * event loop thread will be created
     */
    clients.c = libh2o_websocket_client_start(&client_init);

    clients.nclients = argc;
    clients.clients = malloc(sizeof(struct websocket_client_state_t) * argc);
    memset(clients.clients, 0x00,
           sizeof(struct websocket_client_state_t) * argc);

    /**
     * 2: create websocket client request
     * on_connected and on handshaked will be called back
     */
    struct websocket_client_req_t req = {"http://127.0.0.1:7890/",
                                         WEBSOCKET_FRAME_TYPE_TEXT};
    clients.clients[0].clih = libh2o_websocket_client_req(clients.c, &req);

    int i;
    for (i = 1; i < argc; ++i) {
        req.url = argv[i];
        clients.clients[i].clih = libh2o_websocket_client_req(clients.c, &req);
    }

    h2o_srand();
    while (running) {
        struct websocket_client_state_t *cli;
        int state;

        i = h2o_rand() % clients.nclients;
        cli = clients.clients + i;

        state = __sync_fetch_and_or(&cli->state, 0);
        if (state > WEBSOCKET_CLIENT_STATE_HANDSHAKED && cli->clih) {
            for (int i = 0; i < 10; ++i) {
                const char *p = "hello server\n";
                const char *buf = strdup(p);
                /**
                 * 3: send data for this connection
                 * on_sent will be called back
                 */
                libh2o_websocket_client_send(cli->clih, buf, strlen(buf) + 1);
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
        usleep(10000);
    }

    libh2o_websocket_client_stop(clients.c);

    free(clients.clients);
    return 0;
}
#endif
