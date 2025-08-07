/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : h2o_http_client.h
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_H2OHTTPCLIENT_H__
#define __INCLUDE_H2OHTTPCLIENT_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <libh2o_log.h>
#include <libh2o_http_client/libh2o_http_client.h>
#include "iclient.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
/* Default I/O timeout in milliseconds */
#ifndef HTTP_CLIENT_IO_TIMEOUT_MS
#define HTTP_CLIENT_IO_TIMEOUT_MS (30000)
#endif

/* Default Connect timeout in milliseconds */
#ifndef HTTP_CLIENT_CONNECT_TIMEOUT_MS
#define HTTP_CLIENT_CONNECT_TIMEOUT_MS (10000)
#endif

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
/* Http client request */
struct http_cli_req_t {
    struct cli_req_t super;
    struct http_client_req_t req;
};

struct http_resp_header_t {
    int version;
    int status;
    h2o_iovec_t msg;
    h2o_headers_t headers;
};

/*****************************************************************************
 *                       Global Variables Prototype Section                  *
 *****************************************************************************/
extern const char METHOD_GET[];
extern const char METHOD_POST[];
extern const char METHOD_PUT[];

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

class IHttpRequest : public RefBase
{
  public:
    /**
     * @brief Cancel the in flight http request
     * @return SUCCESS when success or else error
     */
    virtual int Cancel() = 0;

    /**
     * @brief Get error message
     * @return error message when has or else null pointer
     */
    virtual const char *GetErrorMessage() { return NULL; }

  protected:
    virtual ~IHttpRequest() {}
};

using SpIHttpRequest = foundation::sp<IHttpRequest>;

/**
 * @brief Http client event loop and request manager, run multiple clients in
 * one loop
 */
class H2oHttpClient : public IClient
{
  public:
    explicit H2oHttpClient(bool async, const char *cert_file,
                           const char *cli_cer, const char *cli_key,
                           uint32_t timeout, uint32_t connect_timeout);

    virtual int DoRequest(const struct cli_req_t *req,
                          struct cli_identity_t *cli);

    virtual int Cancel(const struct cli_identity_t *cli);

    virtual uint32_t StartTimer(void (*timedout)(void *param, uint32_t),
                                void *param, uint32_t timeout_ms, bool repeat);

    virtual void StopTimer(uint32_t tm);

  protected:
    virtual ~H2oHttpClient();

  private:
    int on_connected(const struct http_client_handle_t *clih);

    int on_head(int version, int status, h2o_iovec_t msg, h2o_header_t *headers,
                size_t num_headers, const struct http_client_handle_t *clih);

    int on_body(void *buf, size_t len, const struct http_client_handle_t *clih);

    void on_finish(const char *err, const struct http_client_handle_t *clih);

    void on_fill_request_body(const struct http_client_handle_t *clih);

    static int
    cb_http_client_on_connected(void *param,
                                const struct http_client_handle_t *clih);
    static int cb_http_client_on_head(void *param, int version, int status,
                                      h2o_iovec_t msg, h2o_header_t *headers,
                                      size_t num_headers,
                                      const struct http_client_handle_t *clih);
    static int cb_http_client_on_body(void *param, void *buf, size_t len,
                                      const struct http_client_handle_t *clih);
    static void
    cb_http_client_on_finish(void *param, const char *err,
                             const struct data_statistics_t *statistics,
                             const struct http_client_handle_t *clih);
    static void
    cb_http_client_fill_request_body(void *param,
                                     const struct http_client_handle_t *clih);

  private:
    struct http_client_status_t {
        struct cli_req_t super;
        const struct http_client_handle_t *clih;
    };
    Mutex mutex_;
    Condition cond_;
    struct libh2o_http_client_ctx_t *client_ctx_;
    xmap<uint32_t, struct http_client_status_t *> reqs_;

  private:
    DISALLOW_COPY_AND_ASSIGN(H2oHttpClient);
};

inline SpIClient createSpH2oHttpClient(bool async, const char *cert_file,
                                       const char *cli_cer, const char *cli_key,
                                       uint32_t timeout,
                                       uint32_t connect_timeout)
{
    return new H2oHttpClient(async, cert_file, cli_cer, cli_key, timeout,
                             connect_timeout);
}

/* helpers */
inline bool IsHttpStatusOk(int status) { return status == 200; }
inline bool IsHttpStatusNoContent(int status) { return status == 204; }
inline bool IsHttpStatusOkOrPartialContent(int status)
{
    return status == 200 || status == 206;
}
inline bool IsHttpStatusMovedPermanently(int status) { return status == 301; }
inline bool IsHttpStatusNotModified(int status) { return status == 304; }
inline bool IsHttpStatusNotFound(int status) { return status == 404; }
inline bool IsHttpStatusInformational(int status)
{
    return status >= 100 && status < 200;
}
inline bool IsHttpStatusSuccessful(int status)
{
    return status >= 200 && status < 300;
}
inline bool IsHttpStatusRedirection(int status)
{
    return status >= 300 && status < 400;
}
inline bool IsHttpStatusClientError(int status)
{
    return status >= 400 && status < 500;
}
inline bool IsHttpStatusServerError(int status)
{
    return status >= 500 && status < 600;
}
inline int HttpStatusToError(int status)
{
    ASSERT(!IsHttpStatusOk(status));
    return (status >= 100 && status < 600) ? -status : FAILURE;
}
#endif

#endif /* __INCLUDE_H2OHTTPCLIENT_H__ */
