/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : http_request.cpp
 *   CREATE DATE : 2022-07-30
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "http_request.h"

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
int HttpRequest::cli_callback(void *user, int evt, void *data, size_t length,
                              const struct cli_identity_t *cli)
{
    HttpRequest *_this = (HttpRequest *)user;
    H2O_LOGV("HttpRequest: cli_callback: evt=0x%08x data=%p length=%zu id=%u",
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
    case CLI_EVT_HOSTRESOLVED:
    case CLI_EVT_CONNECTED:
    case CLI_EVT_HTTP_FILL_REQ_BODY:
    default:
        return 0;
    }
}

int HttpRequest::on_finish(const char *err)
{
    struct http_req_meta_t *meta = &meta_;
    H2O_LOGD("HttpRequest::on_finish() status=%d version=0x%x body=(%p %zu)",
              meta->status, meta->version, meta->body.entries, meta->body.size);
    if (err && err != h2o_httpclient_error_is_eos) {
        meta->network_error = err;
        H2O_LOGI("HttpRequest: err='%s'", err);
    }
#ifdef ENABLE_TEST
    if (!is_status_ok()) {
        if (meta->content_type_text && meta->body.size > 0) {
            H2O_LOGD("HttpAsyncRequest: response body='%.*s'",
                      MIN_T((int)meta->body.size, LOG_MAX_MSG_SIZE),
                      meta->body.entries);
        }
    }
#endif
    return 0;
}

int HttpRequest::on_head(int version, int status, h2o_iovec_t msg,
                         const h2o_headers_t *headers)
{
    struct http_req_meta_t *meta = &meta_;
    H2O_LOGV("HttpRequest::on_head() status=%d version=%d", status, version);
    meta->status = status;
    meta->version = version;

    for (size_t i = 0; i < ARRAY_SIZE(meta->tokens); ++i) {
        const h2o_token_t *token = meta->tokens[i];
        if (!token) break;
        ssize_t index = h2o_find_header(headers, token, -1);
        if (index != -1) {
            const char *name = headers->entries[index].orig_name;
            if (name == NULL) name = headers->entries[index].name->base;
            H2O_LOGV("%.*s: %.*s", (int)headers->entries[index].name->len,
                      name, (int)headers->entries[index].value.len,
                      headers->entries[index].value.base);
            h2o_iovec_t value =
                h2o_strdup(NULL, headers->entries[index].value.base,
                           headers->entries[index].value.len);
            h2o_add_header(NULL, &meta->headers, token, NULL, value.base,
                           value.len);
        }
    }

#ifdef ENABLE_TEST
    if (!is_status_ok()) {
        ssize_t index = h2o_find_header(headers, H2O_TOKEN_CONTENT_TYPE, -1);
        if (index != -1) {
            const char *name = headers->entries[index].orig_name;
            if (name == NULL) name = headers->entries[index].name->base;
            H2O_LOGV("%.*s: %.*s", (int)headers->entries[index].name->len,
                      name, (int)headers->entries[index].value.len,
                      headers->entries[index].value.base);
            if (h2o_strstr(headers->entries[index].value.base,
                           headers->entries[index].value.len,
                           H2O_STRLIT("text")) != SIZE_MAX) {
                meta->content_type_text = 0x01;
            }
        }
    }
#endif
    return 0;
}

int HttpRequest::on_body(void *buf, size_t len)
{
    struct http_req_meta_t *meta = &meta_;
    h2o_vector_reserve(NULL, &meta->body, meta->body.size + len);
    memcpy(meta->body.entries + meta->body.size, buf, len);
    meta->body.size += len;
    return 0;
}

HttpRequest::HttpRequest(const SpIClient &cli, const h2o_token_t *token[],
                         size_t num_token)
    : http_client_(cli)
{
    memset(&meta_, 0x00, sizeof(meta_));
    if (token && num_token > 0) {
        if (num_token > ARRAY_SIZE(meta_.tokens)) {
            ASSERT(0);
            num_token = ARRAY_SIZE(meta_.tokens);
        }
        memcpy(meta_.tokens, token, num_token * sizeof(meta_.tokens[0]));
    }
}

HttpRequest::~HttpRequest()
{
    struct http_req_meta_t *meta = &meta_;
    if (meta->headers.size > 0) {
        for (size_t i = 0; i < meta->headers.size; ++i) {
            h2o_header_t *h = &meta->headers.entries[i];
            if (h->value.base) free(h->value.base);
        }
        free(meta->headers.entries);
    }
    if (meta->body.entries) {
        free(meta->body.entries);
    }
}

const h2o_header_t *
HttpRequest::GetResponseHeader(const h2o_token_t *token) const
{
    const struct http_req_meta_t *meta = &meta_;
    ssize_t index = h2o_find_header(&meta->headers, token, -1);
    if (index != -1) {
        return &meta->headers.entries[index];
    }
    return NULL;
}

int HttpRequest::DoHttpRequest(const struct http_client_req_t *req)
{
    int rc;

    if (req == NULL) return FAILURE;
    if (req->url == NULL) {
        ASSERT(0);
        return FAILURE;
    }
    if (req->fill_request_body != NULL) {
        ASSERT(0);
        return FAILURE;
    }

    if (http_client_->IsAsync()) {
        H2O_LOGW("http client context is async");
        return FAILURE;
    }

    H2O_LOGD("HttpRequest: doing '%s %.*s'", req->method ? req->method : "GET",
              LOG_MAX_MSG_SIZE, req->url);
#ifdef ENABLE_TEST
    const size_t len = strlen(req->url);
    if (len > LOG_MAX_MSG_SIZE) {
        ssize_t remain = len - LOG_MAX_MSG_SIZE;
        const char *p = req->url + LOG_MAX_MSG_SIZE;
        do {
            H2O_LOGD("\t\t'%.*s'", LOG_MAX_MSG_SIZE, p);
            remain -= LOG_MAX_MSG_SIZE;
            if (remain <= 0) break;
            p += LOG_MAX_MSG_SIZE;
        } while (true);
    }
#endif
    struct http_cli_req_t r;
    memset(&r, 0x00, sizeof(r));
    r.super.user = this;
    r.super.cb = cli_callback;
    r.req = *req;

    rc = http_client_->DoRequest(&r.super, &meta_.cli);
    RETURN_IF_FAIL(rc, FAILURE);

    return is_status_ok() ? SUCCESS : HttpStatusToError(meta_.status);
}

int HttpRequest::Cancel() { return http_client_->Cancel(&meta_.cli); }
