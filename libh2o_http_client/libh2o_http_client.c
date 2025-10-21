/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_http_client.c
 *   CREATE DATE : 2018-12-10
 *   MODULE      : libh2o_http_client
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef LOG_TAG
#define LOG_TAG "H2O.http"
#endif
// #define LOG_NDEBUG 0

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "h2o.h"
#if defined(HAVE_PRCTL)
#include <sys/prctl.h>
#endif

#include "libh2o_log.h"
#include "libh2o_cmn.h"
#include "libh2o_http_client.h"

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
// #define DEBUG_SERIAL 1

#define NOTIFICATION_CONN 0
#define NOTIFICATION_START_TIMER 1
#define NOTIFICATION_STOP_TIMER 2
#define NOTIFICATION_QUIT 0xFFFFFFFF

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
/**
 * http client context type
 */
struct libh2o_http_client_ctx_t {
    pthread_t tid; /* event loop thread id */
    h2o_sem_t sem;
    h2o_httpclient_ctx_t ctx; /* http client context */
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t notifications;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_linklist_t conns;
    h2o_linklist_t timers;
    struct http_client_init_t client_init;
    h2o_httpclient_connection_pool_t *connpool;
    uint64_t websocket_timeout;
    h2o_socketpool_t *sockpool;
    SSL_CTX *ssl_ctx;
    uint32_t serial_counter;
    uint32_t timer_counter;
    int exit_loop;
    int delay_interval_ms;
};

/**
 * MUST the first member for sub struct
 */
struct notification_cmn_t {
    h2o_multithread_message_t
        super; /* used to call h2o_multithread_send_message() */
    struct libh2o_http_client_ctx_t *c;
    uint32_t cmd;
};

struct notification_conn_t {
    struct notification_cmn_t cmn;
    h2o_httpclient_t *client;
    h2o_timer_t _timeout;
    h2o_url_t url_parsed;
    struct http_client_req_t req;
    h2o_iovec_t org_body;
    h2o_mem_pool_t pool;
    struct http_client_handle_t clih;
    struct data_statistics_t statistics;
};

struct libh2o_evloop_timer_t {
    struct libh2o_evloop_timedout_t to;
    uint32_t id;
    uint32_t timeout_ms;
    uint32_t flags;
};

struct notification_start_timer_t {
    struct notification_cmn_t cmn;
    struct libh2o_evloop_timer_t timer;
    h2o_timer_t _timeout;
};

struct notification_stop_timer_t {
    struct notification_cmn_t cmn;
    uint32_t id;
};

struct notification_quit_t {
    struct notification_cmn_t cmn;
};

/*****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/
static const char __httpclient_error_callback[] = "callback error";
static const char __httpclient_error_url[] = "url error";
static const char __httpclient_error_cancelled[] = "user cancelled";
static const char __httpclient_error_evloop_quiting[] = "evloop quiting";

/*****************************************************************************
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

static void user_timeout_cb(h2o_timer_t *entry);
static struct notification_start_timer_t *
find_notification_timer(struct libh2o_http_client_ctx_t *c, uint32_t id);
static void
release_notification_timer(struct notification_start_timer_t *timer);

/*****************************************************************************
 *                       Functions Implement Section                         *
 *****************************************************************************/
static void notify_thread_quit(struct libh2o_http_client_ctx_t *c)
{
    struct notification_quit_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_QUIT;
    msg->cmn.c = c;

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
}

static void dup_req(struct http_client_req_t *dst,
                    const struct http_client_req_t *src)
{
    int i;
    dst->url = strdup(src->url);
    dst->method = src->method; /* const string */
    if (src->body.base != NULL && src->body.len > 0) {
        dst->body.len = src->body.len;
        dst->body.base = h2o_mem_alloc(dst->body.len);
        memcpy(dst->body.base, src->body.base, dst->body.len);
    }
    dst->fill_request_body = src->fill_request_body;

    for (i = 0; i < HTTP_REQUEST_HEADER_MAX; ++i) {
        if (src->header[i].token == NULL) break;
        // ASSERT(h2o_iovec_is_token(&src->header[i].token->buf));
        dst->header[i].token = src->header[i].token;
        dst->header[i].value = h2o_strdup(NULL, src->header[i].value.base,
                                          src->header[i].value.len);
    }
}

static void free_req(struct notification_conn_t *conn)
{
    struct http_client_req_t *req = &conn->req;
    int i;
    ASSERT(req->url);
    free(req->url);
    if (conn->org_body.base != NULL && req->body.base != conn->org_body.base) {
        req->body.base = conn->org_body.base;
    }
    if (req->body.base) {
        free(req->body.base);
    }
    for (i = 0; i < HTTP_REQUEST_HEADER_MAX; ++i) {
        if (req->header[i].token == NULL) break;
        if (req->header[i].value.base) free(req->header[i].value.base);
    }
}

static struct notification_conn_t *
notify_thread_connect(struct libh2o_http_client_ctx_t *c,
                      struct http_client_req_t *req, void *user)
{
    struct notification_conn_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_CONN;
    msg->cmn.c = c;

    dup_req(&msg->req, req);

    do {
        msg->clih.serial = __sync_add_and_fetch(&c->serial_counter, 1);
    } while (msg->clih.serial == 0);
    msg->clih.user = user;
#ifdef DEBUG_SERIAL
    H2O_LOGV("create serial: %u", msg->clih.serial);
#endif

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
    return msg;
}

static struct notification_start_timer_t *
notify_thread_start_timer(struct libh2o_http_client_ctx_t *c,
                          struct libh2o_evloop_timedout_t *to,
                          uint32_t timeout_ms, uint32_t flags)
{
    struct notification_start_timer_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_START_TIMER;
    msg->cmn.c = c;
    msg->timer.to = *to;
    msg->timer.timeout_ms = timeout_ms;
    msg->timer.flags = flags;
    do {
        msg->timer.id = __sync_add_and_fetch(&c->timer_counter, 1);
    } while (msg->timer.id == 0);

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
    return msg;
}

static void notify_thread_stop_timer(struct libh2o_http_client_ctx_t *c,
                                     uint32_t id)
{
    struct notification_stop_timer_t *msg = h2o_mem_alloc(sizeof(*msg));
    memset(msg, 0x00, sizeof(*msg));

    msg->cmn.cmd = NOTIFICATION_STOP_TIMER;
    msg->cmn.c = c;
    msg->id = id;

    h2o_multithread_send_message(&c->notifications, &msg->cmn.super);
}

static void release_notification_conn(struct notification_conn_t *conn)
{
#ifdef DEBUG_SERIAL
    H2O_LOGV("release serial: %u", conn->clih.serial);
#endif
    if (h2o_linklist_is_linked(&conn->cmn.super.link)) {
        h2o_linklist_unlink(&conn->cmn.super.link);
    }
    if (h2o_timer_is_linked(&conn->_timeout)) {
        h2o_timer_unlink(&conn->_timeout);
    }
    free_req(conn);
    h2o_mem_clear_pool(&conn->pool);
    free(conn);
}

static void on_notification(h2o_multithread_receiver_t *receiver,
                            h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_cmn_t *cmn = (struct notification_cmn_t *)msg;
        struct libh2o_http_client_ctx_t *c = cmn->c;

        h2o_linklist_unlink(&msg->link);
        if (cmn->cmd == NOTIFICATION_CONN) {
            struct notification_conn_t *conn =
                (struct notification_conn_t *)cmn;
            h2o_mem_init_pool(&conn->pool);
            /* parse URL */
            if (h2o_url_parse(conn->req.url, SIZE_MAX, &conn->url_parsed) !=
                0) {
                H2O_LOGW("unrecognized type of URL: %s", conn->req.url);
                on_error(conn, "on_notification", __httpclient_error_url);
                continue;
            }
            h2o_linklist_insert(&c->conns, &msg->link);
            h2o_httpclient_connect(&conn->client, &conn->pool, conn,
                                   &conn->cmn.c->ctx, conn->cmn.c->connpool,
                                   &conn->url_parsed, on_connect);
        } else if (cmn->cmd == NOTIFICATION_START_TIMER) {
            struct notification_start_timer_t *timer =
                (struct notification_start_timer_t *)msg;
            h2o_linklist_insert(&c->timers, &msg->link);
            timer->_timeout.cb = user_timeout_cb;
            h2o_timer_link(c->ctx.loop, timer->timer.timeout_ms,
                           &timer->_timeout);
        } else if (cmn->cmd == NOTIFICATION_STOP_TIMER) {
            struct notification_stop_timer_t *stop_timer_msg =
                (struct notification_stop_timer_t *)msg;
            struct notification_start_timer_t *timer =
                find_notification_timer(c, stop_timer_msg->id);
            if (timer) {
                release_notification_timer(timer);
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

static int callback_on_connected(struct notification_conn_t *conn)
{
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    struct http_client_init_t *p = &c->client_init;

    if (p->cb.on_connected) {
        return p->cb.on_connected(p->cb.param, &conn->clih);
    }
    return 0;
}

static void callback_on_fill_request_body(struct notification_conn_t *conn)
{
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    struct http_client_init_t *p = &c->client_init;

    ASSERT(conn->req.fill_request_body);
    conn->req.fill_request_body(p->cb.param, &conn->clih);
}

static int callback_on_head(struct notification_conn_t *conn, int version,
                            int status, h2o_iovec_t msg, h2o_header_t *headers,
                            size_t num_headers)
{
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    struct http_client_init_t *p = &c->client_init;

    if (p->cb.on_head) {
        return p->cb.on_head(p->cb.param, version, status, msg, headers,
                             num_headers, &conn->clih);
    }
    return 0;
}

static int callback_on_body(struct notification_conn_t *conn, void *buf,
                            size_t len)
{
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    struct http_client_init_t *p = &c->client_init;

    if (p->cb.on_body) {
        return p->cb.on_body(p->cb.param, buf, len, &conn->clih);
    }
    return 0;
}

static void callback_on_on_finish(struct notification_conn_t *conn,
                                  const char *err)
{
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    struct http_client_init_t *p = &c->client_init;

    if (p->cb.on_finish) {
        p->cb.on_finish(p->cb.param, err, &conn->statistics, &conn->clih);
    }
}

static void release_linkedlist(struct libh2o_http_client_ctx_t *c,
                               h2o_linklist_t *messages, const char *err)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_conn_t *conn = (struct notification_conn_t *)msg;
        ASSERT(c == conn->cmn.c);
        h2o_linklist_unlink(&msg->link);

        callback_on_on_finish(conn, err);
        release_notification_conn(conn);
    }
}

static void release_conns(struct libh2o_http_client_ctx_t *c, const char *err)
{
    release_linkedlist(c, &c->conns, err);
}

static void on_error(struct notification_conn_t *conn, const char *prefix,
                     const char *err)
{
    ASSERT(err != NULL);
    // H2O_LOGW("%s:%s", prefix, err);
    callback_on_on_finish(conn, err);
    release_notification_conn(conn);
}

static int on_body(h2o_httpclient_t *client, const char *errstr)
{
    int rc = 0;
    struct notification_conn_t *conn = client->data;
    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        on_error(conn, "on_body", errstr);
        return -1;
    }
    size_t size = (*client->buf)->size;
    if (size > 0) {
        rc = callback_on_body(conn, (*client->buf)->bytes, size);
        conn->statistics.bytes_read += size;
        h2o_buffer_consume(&(*client->buf), size);
    }

    if (errstr == h2o_httpclient_error_is_eos) {
        on_error(conn, "on_body", errstr);
    } else if (rc) {
        on_error(conn, "on_body", __httpclient_error_callback);
        return -1;
    }

    return 0;
}

h2o_httpclient_body_cb on_head(h2o_httpclient_t *client, const char *errstr,
                               int version, int status, h2o_iovec_t msg,
                               h2o_header_t *headers, size_t num_headers,
                               int header_requires_dup)
{
    int rc;
    struct notification_conn_t *conn = client->data;

    if (errstr != NULL && errstr != h2o_httpclient_error_is_eos) {
        on_error(conn, "on_head", errstr);
        return NULL;
    }

    rc = callback_on_head(conn, version, status, msg, headers, num_headers);
    if (errstr == h2o_httpclient_error_is_eos) {
        on_error(conn, "on_head", errstr);
        return NULL;
    } else if (rc) {
        on_error(conn, "on_head", __httpclient_error_callback);
        return NULL;
    }
    return on_body;
}

static void do_fill_request_body(struct notification_conn_t *conn,
                                 h2o_iovec_t *reqbuf)
{
    if (conn->req.body.len > 0) {
        if (conn->org_body.len == 0) {
            conn->org_body = conn->req.body;
        }
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
        reqbuf->len =
            MIN(conn->req.body.len, conn->cmn.c->client_init.chunk_size);
#undef MIN
        reqbuf->base = conn->req.body.base;
        conn->req.body.len -= reqbuf->len;
        conn->req.body.base += reqbuf->len;
    } else {
        *reqbuf = h2o_iovec_init(NULL, 0);
    }
}

static void timeout_cb(h2o_timer_t *entry)
{
    h2o_iovec_t reqbuf;
    struct notification_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, _timeout, entry);
    ASSERT(!h2o_timer_is_linked(&conn->_timeout));
    if (conn->req.fill_request_body) {
        callback_on_fill_request_body(conn);
    }
}

static void release_notification_timer(struct notification_start_timer_t *timer)
{
    if (h2o_timer_is_linked(&timer->_timeout))
        h2o_timer_unlink(&timer->_timeout);
    if (h2o_linklist_is_linked(&timer->cmn.super.link))
        h2o_linklist_unlink(&timer->cmn.super.link);
    free(timer);
}

static void release_timers_linkedlist(struct libh2o_http_client_ctx_t *c,
                                      h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_start_timer_t *timer =
            (struct notification_start_timer_t *)msg;
        ASSERT(c == timer->cmn.c);
        release_notification_timer(timer);
    }
}

static void release_timers(struct libh2o_http_client_ctx_t *c)
{
    release_timers_linkedlist(c, &c->timers);
}

static struct notification_start_timer_t *
find_notification_timer(struct libh2o_http_client_ctx_t *c, uint32_t id)
{
    h2o_linklist_t *messages = &c->timers;
    if (h2o_linklist_is_empty(messages)) return NULL;
    while (1) {
        h2o_multithread_message_t *msg = H2O_STRUCT_FROM_MEMBER(
            h2o_multithread_message_t, link, messages->next);
        struct notification_start_timer_t *timer =
            (struct notification_start_timer_t *)msg;
        ASSERT(c == timer->cmn.c);
        if (timer->timer.id == id) return timer;
        messages = messages->next;
        if (messages == &c->timers) break;
    }
    return NULL;
}

static void user_timeout_cb(h2o_timer_t *entry)
{
    struct notification_start_timer_t *timer = H2O_STRUCT_FROM_MEMBER(
        struct notification_start_timer_t, _timeout, entry);
    ASSERT(!h2o_timer_is_linked(&timer->_timeout));
    timer->timer.to.timedout(timer->timer.to.param, timer->timer.id);
    if (timer->timer.flags & LIBH2O_EVLOOP_TIMER_REPEAT) {
        h2o_timer_link(timer->cmn.c->ctx.loop, timer->timer.timeout_ms,
                       &timer->_timeout);
    } else {
        release_notification_timer(timer);
    }
}

static void proceed_request(h2o_httpclient_t *client, size_t written,
                            int is_end_stream)
{
    struct notification_conn_t *conn = client->data;
    if (conn->req.fill_request_body) {
        if (!h2o_timer_is_linked(&conn->_timeout)) {
            conn->_timeout.cb = timeout_cb;
            h2o_timer_link(client->ctx->loop, conn->cmn.c->delay_interval_ms,
                           &conn->_timeout);
        }
    }
}

h2o_httpclient_head_cb
on_connect(h2o_httpclient_t *client, const char *errstr, h2o_iovec_t *_method,
           h2o_url_t *url, const h2o_header_t **headers, size_t *num_headers,
           h2o_iovec_t *body, h2o_httpclient_proceed_req_cb *proceed_req_cb,
           h2o_httpclient_properties_t *props, h2o_url_t *origin)
{
    int rc;
    struct notification_conn_t *conn = client->data;
    h2o_headers_t headers_vec = (h2o_headers_t){NULL, 0, 0};
    int i;

    if (errstr != NULL) {
        on_error(conn, "on_connect", errstr);
        return NULL;
    }

    rc = callback_on_connected(conn);
    if (rc) {
        on_error(conn, "on_connect", __httpclient_error_callback);
        return NULL;
    }

    *_method = h2o_iovec_init(conn->req.method, strlen(conn->req.method));
    *url = conn->url_parsed;
    *body = h2o_iovec_init(NULL, 0);

    for (i = 0; i < HTTP_REQUEST_HEADER_MAX; ++i) {
        if (conn->req.header[i].token == NULL) break;
        h2o_add_header(&conn->pool, &headers_vec, conn->req.header[i].token,
                       NULL, conn->req.header[i].value.base,
                       conn->req.header[i].value.len);

        if (conn->req.header[i].token == H2O_TOKEN_TRANSFER_ENCODING) {
            /* http1 only */
            if (h2o_memis(conn->req.header[i].value.base,
                          conn->req.header[i].value.len,
                          H2O_STRLIT("chunked"))) {
                static const int chunked = 1;
                props->chunked = (int *)&chunked;
            }
        }
    }

    if (conn->req.body.len > 0) {
        char *clbuf = h2o_mem_alloc_pool(&conn->pool, char,
                                         sizeof(H2O_UINT32_LONGEST_STR) - 1);
        size_t clbuf_len = sprintf(clbuf, "%d", (int)conn->req.body.len);
        h2o_add_header(&conn->pool, &headers_vec, H2O_TOKEN_CONTENT_LENGTH,
                       NULL, clbuf, clbuf_len);
        *body = h2o_iovec_init(conn->req.body.base, conn->req.body.len);
        conn->statistics.bytes_written += conn->req.body.len;
    } else if (conn->req.fill_request_body) {
        *proceed_req_cb = proceed_request;
        conn->_timeout.cb = timeout_cb;
        h2o_timer_link(client->ctx->loop, conn->cmn.c->delay_interval_ms,
                       &conn->_timeout);
    }

    *headers = headers_vec.entries;
    *num_headers = headers_vec.size;
    return on_head;
}

static int cli_key_file_passwd_cb(char *buf, int size, int rwflag, void *u)
{
    struct libh2o_http_client_ctx_t *c = u;

    if (c->client_init.ssl_init.passwd_cb) {
        return c->client_init.ssl_init.passwd_cb(buf, size, rwflag,
                                                 c->client_init.cb.param);
    }
    ASSERT(0);
    return 0;
}

static void init_openssl(struct libh2o_http_client_ctx_t *c)
{
    if (c->client_init.ssl_init.cert_file) {
        int rc;

        libh2o_ssl_init();

        c->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
        if (strchr(c->client_init.ssl_init.cert_file, ':') == NULL) {
            SSL_CTX_load_verify_locations(
                c->ssl_ctx, c->client_init.ssl_init.cert_file, NULL);
        } else {
            char *tmp = strdup(c->client_init.ssl_init.cert_file);
            if (tmp) {
                const char *cer = tmp;
                while (*cer) {
                    char *p = strchr(cer, ':');
                    if (p == NULL) {
                        SSL_CTX_load_verify_locations(c->ssl_ctx, cer, NULL);
                        break;
                    }
                    *p++ = '\0';
                    SSL_CTX_load_verify_locations(c->ssl_ctx, cer, NULL);
                    cer = p;
                }
                free(tmp);
            }
        }
#if 0 // !defined(__ANDROID__)
#define LOAD_VERIFY_LOCATION(location)                                         \
    do {                                                                       \
        if (0 == access(location, F_OK)) {                                     \
            SSL_CTX_load_verify_locations(c->ssl_ctx, location, NULL);         \
        }                                                                      \
    } while (0)

        /* Debian/Ubuntu/Gentoo etc. */
        LOAD_VERIFY_LOCATION("/etc/ssl/certs/ca-certificates.crt");
        /* Fedora/RHEL 6 */
        // LOAD_VERIFY_LOCATION("/etc/pki/tls/certs/ca-bundle.crt");
        /* CentOS/RHEL 7 */
        // LOAD_VERIFY_LOCATION(
        //    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
        /* OpenSUSE */
        // LOAD_VERIFY_LOCATION("/etc/ssl/ca-bundle.pem");
        /* OpenELEC */
        // LOAD_VERIFY_LOCATION("/etc/pki/tls/cacert.pem");
#undef LOAD_VERIFY_LOCATION
#endif
        SSL_CTX_set_verify(c->ssl_ctx,
                           c->client_init.verify_none
                               ? SSL_VERIFY_NONE
                               : SSL_VERIFY_PEER |
                                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
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
                H2O_LOGW("Error setting the certificate file");
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
                H2O_LOGW("Error setting the key file");
                goto ERROR;
            }

            /* Make sure the key and certificate file match */
            rc = SSL_CTX_check_private_key(c->ssl_ctx);
            ASSERT(rc > 0);
            if (rc <= 0) {
                H2O_LOGW("Private key does not match the certificate public key");
                goto ERROR;
            }
        }
    }

    return;

ERROR:
    c->exit_loop = 1;
    return;
}

static void release_openssl(struct libh2o_http_client_ctx_t *c)
{
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
    }
}

static void init_conn_poll(struct libh2o_http_client_ctx_t *c)
{
    h2o_httpclient_connection_pool_t *connpool;
    h2o_socketpool_t *sockpool;

    connpool = h2o_mem_alloc(sizeof(*connpool));
    sockpool = h2o_mem_alloc(sizeof(*sockpool));
    h2o_socketpool_init_global(sockpool, 128);
    h2o_socketpool_set_timeout(sockpool,
                               c->client_init.timeout + 1000 /* in msec */);
    h2o_socketpool_register_loop(sockpool, c->ctx.loop);
    h2o_httpclient_connection_pool_init(connpool, sockpool);
    c->connpool = connpool;
    c->sockpool = sockpool;
}

static void release_h2conns(struct libh2o_http_client_ctx_t *c)
{
    h2o_httpclient_connection_pool_t *pool = c->connpool;
    while (!h2o_linklist_is_empty(&pool->http2.conns)) {
        h2o_linklist_t *node = pool->http2.conns.next;
        int r = h2o_httpclient_close_h2conn(node);
        if (r == 0) {
            h2o_evloop_run(c->ctx.loop, 1);
        }
    }
}

static void release_conn_pool(struct libh2o_http_client_ctx_t *c)
{
    release_h2conns(c);
    h2o_socketpool_dispose(c->sockpool);
    free(c->sockpool);
    free(c->connpool);
}

static void *client_loop(void *arg)
{
    struct libh2o_http_client_ctx_t *c = arg;
#if defined(HAVE_PRCTL)
    prctl(PR_SET_NAME, (unsigned long)"http-evloop", 0, 0, 0);
#endif
#ifdef H2O_THREAD_LOCAL_UNINITIALIZED
    h2o_init_thread();
#endif

    c->ctx.loop = h2o_evloop_create();

    c->queue = h2o_multithread_create_queue(c->ctx.loop);
    h2o_multithread_register_receiver(c->queue, &c->getaddr_receiver,
                                      h2o_hostinfo_getaddr_receiver);
    h2o_multithread_register_receiver(c->queue, &c->notifications,
                                      on_notification);
    h2o_sem_post(&c->sem);

    init_openssl(c);
    init_conn_poll(c);
    h2o_socketpool_set_ssl_ctx(c->sockpool, c->ssl_ctx);

    while (!c->exit_loop) {
        h2o_evloop_run(c->ctx.loop, INT32_MAX);
    }

    while (!h2o_linklist_is_empty(&c->conns)) {
        h2o_evloop_run(c->ctx.loop, 10);
    }

    ASSERT(h2o_linklist_is_empty(&c->conns));
    release_conns(c, __httpclient_error_evloop_quiting);
    release_timers(c);
    h2o_hostinfo_interrupt();

    release_conn_pool(c);
    release_openssl(c);

    h2o_hostinfo_wait();
    h2o_hostinfo_getaddr_receiver(&c->getaddr_receiver,
                                  &c->getaddr_receiver._messages);
    h2o_multithread_unregister_receiver(c->queue, &c->getaddr_receiver);
    h2o_multithread_unregister_receiver(c->queue, &c->notifications);
    h2o_multithread_destroy_queue(c->queue);

    h2o_evloop_destroy(c->ctx.loop);
    /**
     * this will clean thread local data used by pool
     */
    h2o_cleanup_thread();
    return 0;
}

const char *libh2o_http_client_get_version(void) { return H2O_VERSION; }

struct libh2o_http_client_ctx_t *
libh2o_http_client_start(const struct http_client_init_t *client_init)
{
    struct libh2o_http_client_ctx_t *c;

    if (!client_init) return NULL;

    if (client_init->ssl_init.cli_cert_file &&
        !client_init->ssl_init.cli_key_file) {
        H2O_LOGW("missing client key file");
        return NULL;
    }

    if (client_init->ssl_init.cli_key_file &&
        !client_init->ssl_init.cli_cert_file) {
        H2O_LOGW("missing client certificate file");
        return NULL;
    }

    if (client_init->ssl_init.cli_cert_file ||
        client_init->ssl_init.cli_key_file) {
        if (!client_init->ssl_init.cert_file) {
            H2O_LOGW("missing server certificate file");
            return NULL;
        }
    }

    c = h2o_mem_alloc(sizeof(*c));
    if (c) {
        memset(c, 0x00, sizeof(*c));
        h2o_linklist_init_anchor(&c->conns);
        h2o_linklist_init_anchor(&c->timers);
        c->websocket_timeout = client_init->timeout;

        /**
         * init http client context
         */
        c->ctx.getaddr_receiver = &c->getaddr_receiver;
        c->ctx.io_timeout = client_init->timeout;
        c->ctx.connect_timeout = client_init->connect_timeout != 0
                                     ? client_init->connect_timeout
                                     : client_init->timeout;
        c->ctx.first_byte_timeout = client_init->timeout;
        c->ctx.websocket_timeout = &c->websocket_timeout;
        c->ctx.keepalive_timeout = client_init->timeout > 1000
                                       ? client_init->timeout - 1000
                                       : client_init->timeout / 2;
        c->ctx.max_buffer_size = H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE * 2;
        memset(&c->ctx.http2, 0x00, sizeof(c->ctx.http2));
        if (client_init->http2_ratio != 0) {
            c->ctx.http2.max_concurrent_streams = 100;
            c->ctx.http2.ratio = client_init->http2_ratio;
        }

        memcpy(&c->client_init, client_init, sizeof(*client_init));
        if (!c->client_init.chunk_size) {
            c->client_init.chunk_size =
                H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE * 2;
        }

        h2o_sem_init(&c->sem, 0);
        h2o_multithread_create_thread(&c->tid, NULL, client_loop, (void *)c);
        h2o_sem_wait(&c->sem);
    }

    return c;
}

void libh2o_http_client_stop(struct libh2o_http_client_ctx_t *c)
{
    if (!c) return;

    notify_thread_quit(c);
    pthread_join(c->tid, NULL);
    h2o_sem_destroy(&c->sem);
    free(c);
}

const struct http_client_handle_t *
libh2o_http_client_req(struct libh2o_http_client_ctx_t *c,
                       struct http_client_req_t *req, void *user)
{
    struct notification_conn_t *msg;

    if (c == NULL || req == NULL || req->url == NULL) return NULL;
    if (req->fill_request_body && req->body.len) return NULL;

    if (req->method == NULL) req->method = "GET";

    msg = notify_thread_connect(c, req, user);
    return &msg->clih;
}

int libh2o_http_client_send_request_body(
    const struct http_client_handle_t *clih, h2o_iovec_t reqbuf,
    int is_end_stream)
{
    if (clih == NULL || clih->serial == 0) {
        return -1;
    }
    struct notification_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    if (c->tid != pthread_self()) {
        return -1;
    }
    ASSERT(conn->req.fill_request_body);
    if (!conn->client) return -1;
    if (is_end_stream) conn->req.fill_request_body = NULL;

    conn->statistics.bytes_written += reqbuf.len;
    return conn->client->write_req(conn->client, reqbuf, is_end_stream);
}

void libh2o_http_client_cancel(const struct http_client_handle_t *clih)
{
    if (clih == NULL || clih->serial == 0) {
        return;
    }
    struct notification_conn_t *conn =
        H2O_STRUCT_FROM_MEMBER(struct notification_conn_t, clih, clih);
    struct libh2o_http_client_ctx_t *c = conn->cmn.c;
    if (c->tid != pthread_self()) {
        return;
    }
    if (conn->client) {
        conn->client->cancel(conn->client);
        conn->client = NULL;
    }
    on_error(conn, "user cancel", __httpclient_error_cancelled);
}

uint32_t libh2o_http_evloop_start_timer(struct libh2o_http_client_ctx_t *c,
                                        struct libh2o_evloop_timedout_t *to,
                                        uint32_t timeout_ms, uint32_t flags)
{
    struct notification_start_timer_t *msg;
    if (c == NULL || to == NULL) return 0;

    msg = notify_thread_start_timer(c, to, timeout_ms, flags);
    return msg->timer.id;
}

void libh2o_http_evloop_stop_timer(struct libh2o_http_client_ctx_t *c,
                                   uint32_t id)
{
    if (c == NULL || id == 0) return;
    notify_thread_stop_timer(c, id);
}

#ifdef LIBH2O_UNIT_TEST
#include <signal.h>

static int cb_http_client_on_connected(void *param,
                                       const struct http_client_handle_t *clih)
{
    // H2O_LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    return 0;
}

static int cb_http_client_on_head(void *param, int version, int status,
                                  h2o_iovec_t msg, h2o_header_t *headers,
                                  size_t num_headers,
                                  const struct http_client_handle_t *clih)
{
#if 0
    size_t i;
    H2O_LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
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
    for (i = 0; i != num_headers; ++i) {
        const char *name = headers[i].orig_name;
        if (name == NULL) name = headers[i].name->base;
        printf("%.*s: %.*s\n", (int)headers[i].name->len, name, (int)headers[i].value.len, headers[i].value.base);
    }
    printf("\n");
#endif
    return 0;
}

static int cb_http_client_on_body(void *param, void *buf, size_t len,
                                  const struct http_client_handle_t *clih)
{
    // H2O_LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
    // fwrite(buf, 1, len, stdout);
    return 0;
}

static void cb_http_client_on_finish(void *param, const char *err,
                                     const struct data_statistics_t *statistics,
                                     const struct http_client_handle_t *clih)
{
    H2O_LOGV("%s() @line: %d err: %s", __FUNCTION__, __LINE__, err);
}

int libh2o_http_client_test(int argc, char **argv)
{
    struct http_client_init_t client_init;
    memset(&client_init, 0x00, sizeof(client_init));

    libh2o_signal_init();

    client_init.timeout = 30000;         /* 30 sec */
    client_init.connect_timeout = 10000; /* 10 sec */
    client_init.cb.on_connected = cb_http_client_on_connected;
    client_init.cb.on_head = cb_http_client_on_head;
    client_init.cb.on_body = cb_http_client_on_body;
    client_init.cb.on_finish = cb_http_client_on_finish;
    client_init.cb.param = NULL;

    struct libh2o_http_client_ctx_t *c = libh2o_http_client_start(&client_init);

    int counter = 10;
    while (counter-- > 0) {
        struct http_client_req_t req = {
            argc > 1 ? argv[1]
                     : "http://192.168.3.26:8008/styleguide/cppguide.html",
            NULL,
            {0},
            {{0}}};
        const struct http_client_handle_t *clih;
        clih = libh2o_http_client_req(c, &req, NULL);
        usleep(100000);
    }
    libh2o_http_client_stop(c);
    return 0;
}
#endif
