/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : http_downloader.cpp
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <assert.h>
#include <fcntl.h>
#include <cutils/fs.h>
#include <cutils/file.h>
#include "http_downloader.h"

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#define CONTENT_CHANGED(meta)                                                  \
    do {                                                                       \
        H2O_LOGI("%s content changed, range=%zu", (meta)->super.url,          \
                  (meta)->super.range);                                        \
        (meta)->super.range = 0;                                               \
        lseek((meta)->fd, 0, SEEK_SET);                                        \
        if (ftruncate((meta)->fd, (meta)->super.range) < 0) {                  \
            H2O_LOGW("ftruncate error: %s", strerror(errno));                 \
            return -1;                                                         \
        }                                                                      \
    } while (0)

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

static inline int doFallocate(int fd, off_t offset, off_t len)
{
#if defined(__linux__)
    return fallocate(fd, 0, offset, len);
#else
    return posix_fallocate(fd, offset, len);
#endif
}

static inline int checkFdFromPath(const char *save_path)
{
    int fd = -1;
    if (str_has_prefix(save_path, "fd=")) {
        fd = (int32_t)strtol(save_path + 3, NULL, 10);
    }
    return fd;
}

static inline int createFile(const char *save_path)
{
    int fd = checkFdFromPath(save_path);
    if (fd == -1) {
        fd = open(save_path, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
    }
    return fd;
}

int HttpDownloader::cli_callback(void *user, int evt, void *data, size_t length,
                                 const struct cli_identity_t *cli)
{
    HttpDownloader *_this = (HttpDownloader *)user;
    H2O_LOGV(
        "HttpDownloader: cli_callback: evt=0x%08x data=%p length=%zu id=%u",
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

int HttpDownloader::on_finish(const char *err)
{
    struct http_dl_meta_t *meta = &meta_;

    if (meta->chunked) {
        if (isHttpStatusOk(&meta->super) && meta->super.range > 0 &&
            meta->super.len == 0) {
            /* Maybe partial, validate by user */
            meta->super.len = meta->super.range;
        }
    }
    if (is_dl_ok(&meta->super) && meta->state > 0) {
        H2O_LOGD("HttpDownloader: '%s' range=%zu len=%zu OK, ETag: '%s' "
                  "coding=%u max_age=%u",
                  meta->super.url, meta->super.range, meta->super.len,
                  meta->super.http.etag, meta->super.http.coding,
                  meta->super.http.max_age);
        return call_dl_cb(&meta->super, DL_EVT_FINISH);
    }

    if (err && err != h2o_httpclient_error_is_eos) {
        meta->super.network_error = err;
    }
    H2O_LOGW("HttpDownloader: '%s' range=%zu len=%zu error '%s'",
              meta->super.url, meta->super.range, meta->super.len,
              meta->super.network_error ? meta->super.network_error : "");
    return call_dl_cb(&meta->super, DL_EVT_ERROR);
}

int HttpDownloader::on_head(int version, int status, h2o_iovec_t msg,
                            const h2o_headers_t *_headers)
{
    struct http_dl_meta_t *meta = &meta_;
    meta->super.http.status = status;

    H2O_LOGV("%s() @line: %d", __FUNCTION__, __LINE__);

    const h2o_header_t *headers = _headers->entries;
    if (status == 206) { /* Partial Content */
        ssize_t index = h2o_find_header(_headers, H2O_TOKEN_CONTENT_RANGE, -1);
        if (index == -1) {
            H2O_LOGW("missing header: %s", H2O_TOKEN_CONTENT_RANGE->buf.base);
            return -1;
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGD("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            const char *len_str = strchr(headers[index].value.base, '/');
            if (len_str != NULL) {
                len_str += 1;
                size_t len_sz = headers[index].value.len -
                                (len_str - headers[index].value.base);
                // H2O_LOGD("%.*s", len_sz, len_str);
                size_t len = h2o_strtosize(len_str, len_sz);
                if (len == SIZE_MAX) {
                    ASSERT(0);
                    return -1;
                }
                if (meta->super.len != len) {
                    ASSERT(0);
                    meta->super.len = len;
                }
            } else {
                ASSERT(0);
            }
        }
    } else if (status == 200) {
        if (meta->fd == -1) {
            meta->fd = createFile(meta->super.save_path);
        }
        ssize_t index = h2o_find_header(_headers, H2O_TOKEN_CONTENT_LENGTH, -1);
        if (index == -1) {
            H2O_LOGW("missing header: %s", H2O_TOKEN_CONTENT_LENGTH->buf.base);
            index = h2o_find_header(_headers, H2O_TOKEN_TRANSFER_ENCODING, -1);
            if (index == -1) {
                H2O_LOGW("missing header: %s",
                          H2O_TOKEN_TRANSFER_ENCODING->buf.base);
                return -1;
            }
            size_t transfer_encoding_len = headers[index].value.len;
            if (h2o_memis(headers[index].value.base, transfer_encoding_len,
                          H2O_STRLIT("chunked"))) {
                ASSERT(meta->super.len == 0);
                if (meta->super.range > 0) {
                    CONTENT_CHANGED(meta);
                }
                meta->chunked = 0x01;
            } else {
                H2O_LOGW("not chunked");
                return -1;
            }
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGD("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            meta->super.len = h2o_strtosize(headers[index].value.base,
                                            headers[index].value.len);
            if (meta->super.len == SIZE_MAX) {
                ASSERT(0);
                return -1;
            }
            if (meta->super.range > 0) {
                CONTENT_CHANGED(meta);
            }
            if (doFallocate(meta->fd, 0, (off_t)meta->super.len) != 0) {
                H2O_LOGW("fallocate error: %s", strerror(errno));
            }
        }
    } else if (status == 204) { /* No Content */
        meta->super.len = SIZE_MAX;
    } else if (status == 304) { /* Not Modified */
        ASSERT(meta->super.range > 0 && meta->super.len == meta->super.range);
    } else if (status == 404) { /* Not Found */
        meta->super.len = 0;
    } else if ((status == 303)    /* See Other */
               || (status == 302) /* Found */
               || (status == 307) /* Temporary Redirect */
               || (status == 308) /* Permanent Redirect */
               || (status == 301) /* Moved Permanetly */) {
        ssize_t index = h2o_find_header(_headers, H2O_TOKEN_LOCATION, -1);
        if (index == -1) {
            H2O_LOGW("missing header: %s", H2O_TOKEN_LOCATION->buf.base);
            meta->super.url[0] = '\0';
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGV("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            if (headers[index].value.len < sizeof(meta->super.url)) {
                snprintf(meta->super.url, sizeof(meta->super.url), "%.*s",
                         (int)headers[index].value.len,
                         headers[index].value.base);
                H2O_LOGV("url='%s'", meta->super.url);
            } else {
                H2O_LOGW("location size=%zu too big",
                          headers[index].value.len);
                meta->super.url[0] = '\0';
            }
        }
        return -1;
    } else {
        H2O_LOGW("unexpected status: %d", status);
        return -1;
    }

    if (meta->super.http.want_etag) {
        ssize_t index = h2o_find_header(_headers, H2O_TOKEN_ETAG, -1);
        if (index == -1) {
            H2O_LOGW("missing header: '%s'", H2O_TOKEN_ETAG->buf.base);
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGD("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            size_t etag_len = headers[index].value.len;
            if (etag_len >= sizeof(meta->super.http.etag)) {
                H2O_LOGW("etag too long, etag_len=%zu + 1 > %zu", etag_len,
                          sizeof(meta->super.http.etag));
            } else {
                strncpy(meta->super.http.etag, headers[index].value.base,
                        etag_len);
                meta->super.http.etag[etag_len] = '\0';
            }
        }
    }

    if (meta->super.http.want_encoding) {
        ssize_t index =
            h2o_find_header(_headers, H2O_TOKEN_CONTENT_ENCODING, -1);
        if (index == -1) {
            H2O_LOGW("missing header: '%s'",
                      H2O_TOKEN_CONTENT_ENCODING->buf.base);
            meta->super.http.coding = __CODING_INVALID;
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGD("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            size_t coding_len = headers[index].value.len;
            if (h2o_memis(headers[index].value.base, coding_len,
                          H2O_STRLIT("gzip"))) {
                meta->super.http.coding = __CODING_GZIP;
            } else if (h2o_memis(headers[index].value.base, coding_len,
                                 H2O_STRLIT("deflate"))) {
                meta->super.http.coding = __CODING_ZLIB;
            } else {
                meta->super.http.coding = __CODING_INVALID;
            }
        }
    }

    if (meta->super.http.want_cache_control) {
        ssize_t index = h2o_find_header(_headers, H2O_TOKEN_CACHE_CONTROL, -1);
        if (index == -1) {
            H2O_LOGW("missing header: '%s'",
                      H2O_TOKEN_CACHE_CONTROL->buf.base);
        } else {
            const char *name = headers[index].orig_name;
            if (name == NULL) name = headers[index].name->base;
            H2O_LOGD("%.*s: %.*s", (int)headers[index].name->len, name,
                      (int)headers[index].value.len, headers[index].value.base);
            size_t cache_control_len = headers[index].value.len;
            size_t off;

            if ((off = h2o_strstr(headers[index].value.base, cache_control_len,
                                  H2O_STRLIT("s-maxage="))) != SIZE_MAX) {
                char *p = (char *)headers[index].value.base + off;
                uint32_t max_age = 0;
                if (1 == sscanf(p, "s-maxage=%u", &max_age)) {
                    meta->super.http.max_age = max_age;
                }
            } else if ((off = h2o_strstr(headers[index].value.base,
                                         cache_control_len,
                                         H2O_STRLIT("max-age="))) != SIZE_MAX) {
                char *p = (char *)headers[index].value.base + off;
                uint32_t max_age = 0;
                if (1 == sscanf(p, "max-age=%u", &max_age)) {
                    meta->super.http.max_age = max_age;
                }
            } else {
                ASSERT(0);
            }
        }
    }

    meta->state = CLI_EVT_HTTP_HEADER;
    meta->notify_size = meta->super.len / 100;
#ifndef HTTP_DOWNLOADER_NOTIFY_MIN_SIZE
#define HTTP_DOWNLOADER_NOTIFY_MIN_SIZE (4 * 1024 * 1024)
#endif
    if (meta->notify_size < HTTP_DOWNLOADER_NOTIFY_MIN_SIZE)
        meta->notify_size = HTTP_DOWNLOADER_NOTIFY_MIN_SIZE;
    H2O_LOGV("notify_size: %zu", meta->notify_size);
    if (meta->super.http.want_speed) {
        meta->notify_time = systemTime();
    }
    return call_dl_cb(&meta->super, DL_EVT_START);
}

int HttpDownloader::on_body(void *buf, size_t len)
{
    struct http_dl_meta_t *meta = &meta_;
    ASSERT(meta->fd > 0);
    if (!isHttpStatusOkOrPartialContent(&meta->super)) {
#ifdef ENABLE_TEST
        H2O_LOGD("body='%.*s'", (int)len, (char *)buf);
#endif
        return 0;
    }

    size_t left = len;
    while (left > 0) {
        ssize_t rc = TEMP_FAILURE_RETRY(
            write(meta->fd, (char *)buf + (len - left), left));
        if (rc < 0) {
            H2O_LOGW("write error: %s", strerror(errno));
            return -1;
        }
        left -= rc;
    }
    meta->super.range += len;

    meta->notify_range += len;
    if (meta->notify_range >= meta->notify_size) {
        if (meta->super.http.want_speed) {
            int64_t cur_ns = systemTime();
            if (cur_ns > meta->notify_time) {
                meta->super.http.speed =
                    (uint32_t)((double)meta->notify_range * s2ns(1) /
                               (cur_ns - meta->notify_time) / 1024.0);
                meta->notify_time = cur_ns;
            }
        }
        meta->notify_range = 0;
        return call_dl_cb(&meta->super, DL_EVT_PROGRESS);
    }
    return 0;
}

HttpDownloader::HttpDownloader(const SpIClient &cli) : http_client_(cli)
{
    memset(&meta_, 0x00, sizeof(meta_));
}

HttpDownloader::~HttpDownloader()
{
    if (meta_.fd > 0) {
        close(meta_.fd);
    }
}

const struct dl_meta_t *HttpDownloader::GetMeta(int *fd)
{
    if (fd) {
        *fd = GetFd();
    }
    return &meta_.super;
}

int HttpDownloader::GetFd()
{
    int fd = meta_.fd;
    meta_.fd = -1;
    return fd;
}

int HttpDownloader::CheckFd() const { return meta_.fd; }

int HttpDownloader::DownloadFile(const struct dl_meta_t *m)
{
    int rc;

    if (m == NULL) return FAILURE;
    if (m->url[0] == '\0') {
        ASSERT(0);
        return FAILURE;
    }
    if (m->save_path[0] == '\0') {
        ASSERT(0);
        return FAILURE;
    }

    if (m->range > m->len) {
        ASSERT(0);
        return FAILURE;
    }

    H2O_LOGD("HttpDownloader: '%s' to '%s' range=%zu len=%zu", m->url,
              m->save_path, m->range, m->len);

    if (m->range > 0 && m->range == m->len) {
        if (m->http.etag[0] == '\0') {
            H2O_LOGW("missing ETag");
            return FAILURE;
        }
    }

    int fd = checkFdFromPath(m->save_path);
    if (m->range > 0) {
        if (fd == -1) {
            struct stat sb;
            if (stat(m->save_path, &sb) == -1) {
                H2O_LOGW("stat(%s) error: %s", m->save_path, strerror(errno));
                return FAILURE;
            } else if (sb.st_size < m->range) {
                H2O_LOGW("inavlid range: %zu", m->range);
                return FAILURE;
            }
            fd = open(m->save_path, O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                H2O_LOGW("open(%s) error: %s", m->save_path, strerror(errno));
                return FAILURE;
            }
        }
    }

    memcpy(&meta_.super, m, sizeof(meta_.super));
    meta_.fd = fd;

    struct http_cli_req_t r;
    memset(&r, 0x00, sizeof(r));
    r.super.user = this;
    r.super.cb = cli_callback;
    r.req.url = (char *)m->url;
    r.req.method = m->http.method;
    r.req.body = m->http.body;

    int hidx = 0;
    char value[HTTP_REQUEST_HEADER_MAX][256];
    if (m->range > 0) {
        if (m->range != m->len) {
            if (ftruncate(fd, m->range) < 0) {
                H2O_LOGW("ftruncate error: %s", strerror(errno));
                goto error;
            }
        }
        if (m->range == m->len) {
            r.req.header[hidx].token = H2O_TOKEN_IF_NONE_MATCH;
            size_t len = snprintf(value[hidx], 256, "%s", m->http.etag);
            r.req.header[hidx].value = h2o_iovec_init(value[hidx], len);
            hidx++;
        } else {
            lseek(fd, 0, SEEK_END);
            r.req.header[hidx].token = H2O_TOKEN_RANGE;
            size_t len = snprintf(value[hidx], 256, "bytes=%zu-", m->range);
            r.req.header[hidx].value = h2o_iovec_init(value[0], len);
            hidx++;

            if (m->http.etag[0] != '\0') {
                r.req.header[hidx].token = H2O_TOKEN_IF_RANGE;
                size_t len = snprintf(value[hidx], 256, "%s", m->http.etag);
                r.req.header[hidx].value = h2o_iovec_init(value[hidx], len);
                hidx++;
            }
        }
    } else {
        ASSERT(m->http.etag[0] == '\0');
    }

    for (size_t i = 0; i < ARRAY_SIZE(m->http.header); ++i) {
        if (!m->http.header[i].token) break;
        ASSERT(hidx < HTTP_REQUEST_HEADER_MAX);
        r.req.header[hidx] = m->http.header[i];
        hidx++;
    }

    rc = http_client_->DoRequest(&r.super, &meta_.cli);
    if (http_client_->IsAsync()) {
        return rc;
    }

    if (is_dl_ok(&meta_.super)) {
        return SUCCESS;
    }

error:
    return FAILURE;
}

int HttpDownloader::Cancel() { return http_client_->Cancel(&meta_.cli); }
