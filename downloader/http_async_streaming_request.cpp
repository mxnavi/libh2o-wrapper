/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : http_async_streaming_request.cpp
 *   CREATE DATE : 2022-10-13
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "http_async_streaming_request.h"

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
 *                       Functions Implement Section                         *
 *****************************************************************************/
int HttpAsyncStreamingRequest::cli_callback(void *user, int evt, void *data,
                                            size_t length,
                                            const struct cli_identity_t *cli)
{
    HttpAsyncStreamingRequest *_this = (HttpAsyncStreamingRequest *)user;
    H2O_LOGV("HttpAsyncStreamingRequest: cli_callback: evt=0x%08x data=%p "
              "length=%zu id=%u",
              evt, data, length, cli->id);
    switch (evt) {
    case CLI_EVT_HTTP_HEADER: {
        struct http_resp_header_t *h = (struct http_resp_header_t *)data;
        ASSERT(h != NULL && length == sizeof(*h));
        return _this->on_head(h->version, h->status, h->msg, &h->headers);
    }
    case CLI_EVT_HTTP_BODY: {
        return _this->on_body(data, length);
    }
    case CLI_EVT_CLOSED: {
        return _this->on_finish((const char *)data);
    }
    case CLI_EVT_HTTP_FILL_REQ_BODY: {
        ASSERT(data != NULL &&
               length > 0 /* sizeof(struct http_client_handle_t) */);
        return _this->on_fill_request_body((struct http_client_handle_t *)data);
    }
    case CLI_EVT_HOSTRESOLVED:
    case CLI_EVT_CONNECTED:
    default:
        return 0;
    }
}

int HttpAsyncStreamingRequest::on_finish(const char *err)
{
    struct http_req_meta_t *meta = &meta_;
    H2O_LOGD("HttpAsyncStreamingRequest::on_finish() status=%d version=0x%x "
              "streaming=%d body=(%p %zu)",
              meta->status, meta->version, streaming_, meta->body.entries,
              meta->body.size);
    meta->state = CLI_EVT_CLOSED;
    if (err && err != h2o_httpclient_error_is_eos) {
        meta->network_error = err;
    }
    return cb_->OnFinished(this);
}

int HttpAsyncStreamingRequest::on_fill_request_body(
    struct http_client_handle_t *clih)
{
    h2o_iovec_t reqbuf = {NULL, 0};
    int is_end_stream = 1;
    cb_->FillRequstBody(this, &reqbuf, &is_end_stream);
    libh2o_http_client_send_request_body(clih, reqbuf, is_end_stream);
    cb_->FinishIoVec(this, reqbuf);
    return 0;
}

int HttpAsyncStreamingRequest::on_head(int version, int status, h2o_iovec_t msg,
                                       const h2o_headers_t *headers)
{
    struct http_req_meta_t *meta = &meta_;
    H2O_LOGV("HttpAsyncStreamingRequest::on_head() status=%d version=%d",
              status, version);
    meta->status = status;
    meta->version = version;
    return cb_->OnHead(this, status, headers);
}

int HttpAsyncStreamingRequest::on_body(void *buf, size_t len)
{
    struct http_req_meta_t *meta = &meta_;
    if (!streaming_) {
        h2o_vector_reserve(NULL, &meta->body, meta->body.size + len);
        memcpy(meta->body.entries + meta->body.size, buf, len);
        meta->body.size += len;
    }
    return cb_->OnBody(this, buf, len);
}

bool HttpAsyncStreamingRequest::isRequestFinished() const
{
    const struct http_req_meta_t *meta = &meta_;
    return meta->state == CLI_EVT_CLOSED;
}

bool HttpAsyncStreamingRequest::IsHttpStatusOK()
{
    ASSERT(isRequestFinished());
    return is_status_ok();
}

h2o_iovec_t HttpAsyncStreamingRequest::GetResponseBody()
{
    ASSERT(isRequestFinished());
    if (!streaming_) {
        return (h2o_iovec_t){meta_.body.entries, meta_.body.size};
    }
    return (h2o_iovec_t){NULL, 0};
}

const char *HttpAsyncStreamingRequest::GetErrorMessage()
{
    ASSERT(isRequestFinished());
    return meta_.network_error;
}

HttpAsyncStreamingRequest::HttpAsyncStreamingRequest(
    const SpIClient &cli, IHttpAsyncStreamingCallback *cb, bool streaming)
    : http_client_(cli), cb_(cb), streaming_(streaming)
{
    memset(&meta_, 0x00, sizeof(meta_));
}

HttpAsyncStreamingRequest::~HttpAsyncStreamingRequest()
{
    struct http_req_meta_t *meta = &meta_;
    if (meta->body.entries) {
        ASSERT(!streaming_);
        free(meta->body.entries);
    }
}

int HttpAsyncStreamingRequest::DoHttpAsyncStreamingRequest(
    const struct http_client_req_t *req)
{
    int rc;

    if (req == NULL) return FAILURE;
    if (req->url == NULL) {
        ASSERT(0);
        return FAILURE;
    }
    if (cb_ == NULL) {
        ASSERT(0);
        return FAILURE;
    }
    if (!http_client_->IsAsync()) {
        H2O_LOGW("http client context is sync");
        return FAILURE;
    }

    {
        H2O_LOGD("HttpAsyncStreamingRequest: doing '%s %.*s'",
                  req->method ? req->method : "GET", LOG_MAX_MSG_SIZE,
                  req->url);

        struct http_cli_req_t r;
        memset(&r, 0x00, sizeof(r));
        r.super.user = this;
        r.super.cb = cli_callback;
        r.req = *req;

        return http_client_->DoRequest(&r.super, &meta_.cli);
    }
}

int HttpAsyncStreamingRequest::Cancel()
{
    return http_client_->Cancel(&meta_.cli);
}
