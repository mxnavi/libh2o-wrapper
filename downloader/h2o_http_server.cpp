/********** Copyright(C) 2023 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/****************************************************************************
 *   FILE NAME   : h2o_http_server.cpp
 *   CREATE DATE : 2023-03-06
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "h2o_http_server.h"

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/*****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Implement Section *
 *****************************************************************************/

void H2oHttpServer::http_server_on_http_request_cb(void *param,
                                                   struct http_request_t *data)
{
    H2oHttpServer *_this = (H2oHttpServer *)param;
    _this->on_http_request(data);
}

void H2oHttpServer::http_server_on_http_resp_timeout_cb(
    void *param, struct http_request_t *data)
{
    H2oHttpServer *_this = (H2oHttpServer *)param;
    _this->on_http_resp_timeout(data);
}

void H2oHttpServer::http_server_on_finish_http_request_cb(
    void *param, struct http_request_t *data)
{
    H2oHttpServer *_this = (H2oHttpServer *)param;
    _this->on_finish_http_request(data);
}

void H2oHttpServer::http_server_on_ws_recv_cb(
    void *param, void *buf, size_t len, const struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

void H2oHttpServer::http_server_on_ws_sent_cb(
    void *param, void *buf, size_t len, const struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

void H2oHttpServer::http_server_on_ws_connected_cb(
    void *param, const struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

void H2oHttpServer::http_server_on_ws_connection_closed_cb(
    void *param, const struct websocket_handle_t *clih)
{
    LOGV("%s() @line: %d", __FUNCTION__, __LINE__);
}

void H2oHttpServer::on_http_request(struct http_request_t *data)
{
    LOGV("%s() req: %p", __FUNCTION__, data->req);
    l_->OnReq(data);
    libh2o_http_server_queue_response(data);
#if 0
    data->resp.status = 200;
    data->resp.header[0].token = H2O_TOKEN_CONTENT_TYPE;
    data->resp.header[0].value = h2o_iovec_init(H2O_STRLIT("text/plain"));

    data->resp.body.cnt = 2;
    data->resp.body.data[0] =
        h2o_strdup(&data->req->pool, "hello world\n", SIZE_MAX);
    data->resp.body.data[1] =
        h2o_strdup(&data->req->pool, "test...\n", SIZE_MAX);

    libh2o_http_server_queue_response(data);
#endif
}

void H2oHttpServer::on_http_resp_timeout(struct http_request_t *data)
{
    LOGW("%s() req: %p", __FUNCTION__, data->req);
}

void H2oHttpServer::on_finish_http_request(struct http_request_t *data)
{
    LOGV("%s() req: %p", __FUNCTION__, data->req);
}

H2oHttpServer::H2oHttpServer(const char *host, const char *port,
                             const char *cer, const char *key,
                             IHttpRequestListener *l)
    : l_(l), server_ctx_(NULL)
{
    LOGV("H2oHttpServer::H2oHttpServer()");
    /* server init param */
    struct http_server_init_t server_init;
    const char *ports[2];
    ports[0] = port;
    ports[1] = NULL;

    memset(&server_init, 0x00, sizeof(server_init));

    server_init.num_threads = 1;
    server_init.host = host;
    /* server_init.host = "ip6-localhost"; */
    server_init.port = ports;
    server_init.doc_root = "/";
    server_init.resp_timeout = 0;
    server_init.ssl_init.cert_file = cer; // "examples/h2o/server.crt";
    server_init.ssl_init.key_file = key;  // "examples/h2o/server.key";
    server_init.ssl_init.ciphers = "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!"
                                   "IDEA:!NULL:!ADH:!EXP:!SRP:!PSK";

    server_init.cb.param = (void *)this;
    server_init.cb.on_http_req = http_server_on_http_request_cb;
    server_init.cb.on_http_resp_timeout = http_server_on_http_resp_timeout_cb;
    server_init.cb.on_finish_http_req = http_server_on_finish_http_request_cb;
    server_init.cb.on_ws_connected = http_server_on_ws_connected_cb;
    server_init.cb.on_ws_recv = http_server_on_ws_recv_cb;
    server_init.cb.on_ws_sent = http_server_on_ws_sent_cb;
    server_init.cb.on_ws_closed = http_server_on_ws_connection_closed_cb;

    server_ctx_ = libh2o_http_server_start(&server_init);
}

H2oHttpServer::~H2oHttpServer()
{
    LOGV("H2oHttpServer::~H2oHttpServer() in");
    if (server_ctx_ != NULL) {
        libh2o_http_server_stop(server_ctx_);
        server_ctx_ = NULL;
    }
    LOGV("H2oHttpServer::~H2oHttpServer() out");
}

uint32_t H2oHttpServer::StartTimer(void (*timedout)(void *param, uint32_t),
                                   void *param, uint32_t timeout_ms,
                                   bool repeat)
{
    struct libh2o_evloop_timedout_t to = {
        .timedout = timedout,
        .param = param,
    };
    return libh2o_http_server_evloop_start_timer(
        server_ctx_, &to, timeout_ms, repeat ? LIBH2O_EVLOOP_TIMER_REPEAT : 0);
}

void H2oHttpServer::StopTimer(uint32_t tm)
{
    libh2o_http_server_evloop_stop_timer(server_ctx_, tm);
}
