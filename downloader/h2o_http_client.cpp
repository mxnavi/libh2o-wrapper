/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/****************************************************************************
 *   FILE NAME   : h2o_http_client.cpp
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "h2o_http_client.h"

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#define ERASE_NOTIFY_LOCKED(it)                                                \
    do {                                                                       \
        reqs_.erase(it);                                                       \
        if (!IsAsync()) {                                                      \
            cond_.broadcast();                                                 \
        }                                                                      \
    } while (0)

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/*****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/
const char METHOD_GET[] = "GET";
const char METHOD_POST[] = "POST";
const char METHOD_PUT[] = "PUT";

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Implement Section *
 *****************************************************************************/
int H2oHttpClient::cb_http_client_on_connected(
    void *param, const struct http_client_handle_t *clih)
{
    H2oHttpClient *_this = (H2oHttpClient *)param;
    LOGV("H2oHttpClient %s() @line: %d clih: %p %u", __FUNCTION__,
              __LINE__, clih, clih->serial);
    return _this->on_connected(clih);
}

int H2oHttpClient::cb_http_client_on_head(
    void *param, int version, int status, h2o_iovec_t msg,
    h2o_header_t *headers, size_t num_headers,
    const struct http_client_handle_t *clih)
{
    H2oHttpClient *_this = (H2oHttpClient *)param;
    LOGV("H2oHttpClient %s() @line: %d clih: %p %u", __FUNCTION__,
              __LINE__, clih, clih->serial);
    return _this->on_head(version, status, msg, headers, num_headers, clih);
}

int H2oHttpClient::cb_http_client_on_body(
    void *param, void *buf, size_t len, const struct http_client_handle_t *clih)
{
    H2oHttpClient *_this = (H2oHttpClient *)param;
    LOGV("H2oHttpClient %s() @line: %d clih: %p %u", __FUNCTION__,
              __LINE__, clih, clih->serial);
    return _this->on_body(buf, len, clih);
}

void H2oHttpClient::cb_http_client_on_finish(
    void *param, const char *err, const struct data_statistics_t *statistics,
    const struct http_client_handle_t *clih)
{
    H2oHttpClient *_this = (H2oHttpClient *)param;
    _this->on_finish(err, clih);
}

void H2oHttpClient::cb_http_client_fill_request_body(
    void *param, const struct http_client_handle_t *clih)
{
    H2oHttpClient *_this = (H2oHttpClient *)param;
    _this->on_fill_request_body(clih);
}

static int8_t __http2_ratio(void)
{
    const char *env = NULL;
    env = getenv("H2O_HTTP_CLIENT_H2_RATIO");
    if (env) {
        long v = strtol(env, NULL, 0);
        if (v == -1)
            return -1;
        else if (v >= 0 && v <= 100) {
            return (int8_t)v;
        }
    }
    return -1;
}

static uint8_t __verify_none(void)
{
    const char *env = NULL;
    env = getenv("H2O_HTTP_CLIENT_VERIFY_NONE");
    if (env) {
        return 1;
    }
    return 0;
}

H2oHttpClient::H2oHttpClient(bool async, const char *cert_file,
                             const char *cli_cer, const char *cli_key,
                             uint32_t timeout, uint32_t connect_timeout)
    : IClient(async), mutex_(), cond_(), client_ctx_(NULL), reqs_()
{
    LOGV("H2oHttpClient::H2oHttpClient()");
    /* client init param */
    struct http_client_init_t client_init;
    memset(&client_init, 0x00, sizeof(client_init));

    client_init.timeout = timeout;
    client_init.connect_timeout = connect_timeout;
    client_init.cb.on_connected = cb_http_client_on_connected;
    client_init.cb.on_head = cb_http_client_on_head;
    client_init.cb.on_body = cb_http_client_on_body;
    client_init.cb.on_finish = cb_http_client_on_finish;
    client_init.ssl_init.cert_file = cert_file;
    client_init.ssl_init.cli_cert_file = cli_cer;
    client_init.ssl_init.cli_key_file = cli_key;
    client_init.http2_ratio = __http2_ratio();
    client_init.verify_none = __verify_none();
    client_init.cb.param = this;

    libh2o_signal_init();
    client_ctx_ = libh2o_http_client_start(&client_init);
}

H2oHttpClient::~H2oHttpClient()
{
    LOGV("H2oHttpClient::~H2oHttpClient() in");
    if (client_ctx_ != NULL) {
        struct libh2o_http_client_ctx_t *tmp = client_ctx_;
        client_ctx_ = NULL;
        libh2o_http_client_stop(tmp);
    }
    ASSERT(reqs_.empty());
    LOGV("H2oHttpClient::~H2oHttpClient() out");
}

int H2oHttpClient::on_connected(const struct http_client_handle_t *clih)
{
    struct http_client_status_t *user =
        (struct http_client_status_t *)clih->user;
    struct cli_identity_t cli = {clih->serial};
    struct cli_req_t super;
    bool notify = false;

    {
        Mutex::Autolock _l(mutex_);
        if (reqs_.find(clih->serial) != reqs_.end()) {
            super = user->super;
            notify = true;
        }
    }
    if (notify) {
        return call_cli_callback(&super, CLI_EVT_CONNECTED, NULL, 0, &cli);
    }
    return -1;
}

int H2oHttpClient::on_head(int version, int status, h2o_iovec_t msg,
                           h2o_header_t *headers, size_t num_headers,
                           const struct http_client_handle_t *clih)
{
    struct http_client_status_t *user =
        (struct http_client_status_t *)clih->user;
    struct cli_identity_t cli = {clih->serial};
    struct cli_req_t super;
    bool notify = false;

#ifdef ENABLE_TEST
    SHOW_RESPONSE_HEADERS(version, status, msg, headers, num_headers);
#endif
    {
        Mutex::Autolock _l(mutex_);
        if (reqs_.find(clih->serial) != reqs_.end()) {
            super = user->super;
            notify = true;
        }
    }
    if (notify) {
        struct http_resp_header_t resp_header = {
            version,
            status,
            {msg.base, msg.len},
            {headers, num_headers, num_headers}};

        return call_cli_callback(&super, CLI_EVT_HTTP_HEADER, &resp_header,
                                 sizeof(resp_header), &cli);
    }
    return -1;
}

int H2oHttpClient::on_body(void *buf, size_t len,
                           const struct http_client_handle_t *clih)
{
    struct http_client_status_t *user =
        (struct http_client_status_t *)clih->user;
    struct cli_identity_t cli = {clih->serial};
    struct cli_req_t super;
    bool notify = false;

    {
        Mutex::Autolock _l(mutex_);
        if (reqs_.find(clih->serial) != reqs_.end()) {
            super = user->super;
            notify = true;
        }
    }
    if (notify) {
        return call_cli_callback(&super, CLI_EVT_HTTP_BODY, buf, len, &cli);
    }
    return -1;
}

void H2oHttpClient::on_finish(const char *err,
                              const struct http_client_handle_t *clih)
{
    struct http_client_status_t *user =
        (struct http_client_status_t *)clih->user;
    struct cli_identity_t cli = {clih->serial};
    struct cli_req_t super;
    struct http_client_status_t *p = NULL;

    if (err && err != h2o_httpclient_error_is_eos) {
        LOGI("H2oHttpClient::on_finish serial=%u err='%s'", clih->serial,
                  err);
    }
    {
        xmap<uint32_t, struct http_client_status_t *>::iterator it;
        mutex_.lock();
        it = reqs_.find(clih->serial);
        if (it != reqs_.end()) {
            super = user->super;
            mutex_.unlock();
            call_cli_callback(&super, CLI_EVT_CLOSED, (void *)err, 0, &cli);
            mutex_.lock();
            it = reqs_.find(clih->serial); /* find again, in case of Cancel() */
            if (it != reqs_.end()) {
                p = it->second;
                ERASE_NOTIFY_LOCKED(it);
            }
        }
        mutex_.unlock();
    }
    if (p != NULL) {
        ASSERT(p == user);
    }
    free(user);
}

void H2oHttpClient::on_fill_request_body(
    const struct http_client_handle_t *clih)
{
    struct http_client_status_t *user =
        (struct http_client_status_t *)clih->user;
    struct cli_identity_t cli = {clih->serial};
    struct cli_req_t super;
    bool notify = false;

    {
        Mutex::Autolock _l(mutex_);
        if (reqs_.find(clih->serial) != reqs_.end()) {
            super = user->super;
            notify = true;
        }
    }
    if (notify) {
        call_cli_callback(&super, CLI_EVT_HTTP_FILL_REQ_BODY, (void *)clih,
                          sizeof(*clih), &cli);
    } else {
        h2o_iovec_t reqbuf = {NULL, 0};
        libh2o_http_client_send_request_body(clih, reqbuf, 1);
    }
}

int H2oHttpClient::DoRequest(const struct cli_req_t *_req,
                             struct cli_identity_t *cli)
{
    uint32_t serial;
    struct http_cli_req_t *req;
    struct http_client_status_t *p;

    if (cli == NULL) return FAILURE;

    if (client_ctx_ == NULL) {
        goto error;
    }

    req = (struct http_cli_req_t *)_req;
    if (req == NULL) {
        goto error;
    }

    /* Freed in 'on_finish()' */
    p = (struct http_client_status_t *)malloc(sizeof(*p));
    if (p == NULL) {
        goto error;
    }
    memset(p, 0x00, sizeof(*p));
    memcpy(&p->super, &req->super, sizeof(p->super));

    if (req->req.fill_request_body) {
        req->req.fill_request_body = cb_http_client_fill_request_body;
    }
    {
        Mutex::Autolock _l(mutex_);
        const struct http_client_handle_t *clih =
            libh2o_http_client_req(client_ctx_, &req->req, p);
        if (clih == NULL) {
            free(p);
            goto error;
        }
        serial = clih->serial;
        p->clih = clih;
        reqs_.insert(
            std::pair<uint32_t, struct http_client_status_t *>(serial, p));

        /**
         * wait for request finished when sync
         */
        while (!IsAsync()) {
            if (reqs_.find(serial) == reqs_.end()) {
                break;
            }
            cond_.wait(mutex_);
        }
    }
    LOGV("H2oHttpClient::DoRequest(%s) OK", req->req.url);
    cli->id = serial;
    return SUCCESS;

error:
    LOGW("H2oHttpClient::DoRequest() error");
    cli->id = CLI_INVALID_ID;
    return FAILURE;
}

int H2oHttpClient::Cancel(const struct cli_identity_t *cli)
{
    xmap<uint32_t, struct http_client_status_t *>::iterator it;

    LOGV("H2oHttpClient::Cancel()");
    if (cli == NULL) return FAILURE;
    if (cli->id == CLI_INVALID_ID) return FAILURE;

    {
        Mutex::Autolock _l(mutex_);
        it = reqs_.find(cli->id);
        if (it != reqs_.end()) {
            ERASE_NOTIFY_LOCKED(it);
            return SUCCESS;
        }
    }
    return FAILURE;
}

uint32_t H2oHttpClient::StartTimer(void (*timedout)(void *param, uint32_t),
                                   void *param, uint32_t timeout_ms,
                                   bool repeat)
{
    struct libh2o_evloop_timedout_t to = {
        .timedout = timedout,
        .param = param,
    };
    return libh2o_http_evloop_start_timer(
        client_ctx_, &to, timeout_ms, repeat ? LIBH2O_EVLOOP_TIMER_REPEAT : 0);
}

void H2oHttpClient::StopTimer(uint32_t tm)
{
    libh2o_http_evloop_stop_timer(client_ctx_, tm);
}
