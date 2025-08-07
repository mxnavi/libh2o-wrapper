/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : http_streaming_request.h
 *   CREATE DATE : 2022-10-13
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_HTTP_ASYNC_STREAMING_REQUEST_H__
#define __INCLUDE_HTTP_ASYNC_STREAMING_REQUEST_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "h2o_http_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/*****************************************************************************
 *                       Global Variables Prototype Section                  *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

class HttpAsyncStreamingRequest;

/**
 * @brief Http callback interface
 */
class IHttpAsyncStreamingCallback
{
  public:
    virtual int OnHead(HttpAsyncStreamingRequest *r, int status,
                       const h2o_headers_t *headers) = 0;
    virtual int OnBody(HttpAsyncStreamingRequest *r, void *buf, size_t len) = 0;
    virtual int OnFinished(HttpAsyncStreamingRequest *r) = 0;
    virtual int FillRequstBody(HttpAsyncStreamingRequest *r,
                               h2o_iovec_t *reqbuf, int *is_end_stream) = 0;
    virtual void FinishIoVec(HttpAsyncStreamingRequest *r,
                             h2o_iovec_t reqbuf) = 0;
};

/**
 * @brief Represents a http request
 */
class HttpAsyncStreamingRequest : public IHttpRequest
{
  public:
    /**
     * @brief http request with callback
     * @param cli   [I] http client context
     * @param cb    [I] callback, not null
     * @streaming   [I] streaming response body flag
     */
    explicit HttpAsyncStreamingRequest(const SpIClient &cli,
                                       IHttpAsyncStreamingCallback *cb,
                                       bool streaming = true);

    /**
     * @brief Do http request according to the input request param
     * @param req   [I] the input request info
     * @return SUCCESS when success or else error
     */
    int DoHttpAsyncStreamingRequest(const struct http_client_req_t *req);

    /**
     * @brief Cancel the in flight http request
     * @return SUCCESS when success or else error
     */
    virtual int Cancel();

    /**
     * @brief Judge whether the http status code is 200 OK
     * @return true when yes or else false
     * @note called in or after OnFinished() callback
     */
    bool IsHttpStatusOK();

    /**
     * @brief Get response body
     * @return iovec of response body
     * @note called in or after OnFinished() callback
     */
    h2o_iovec_t GetResponseBody();

    /**
     * @brief Get error message
     * @return error message when has or else null pointer
     */
    virtual const char *GetErrorMessage();

  protected:
    virtual ~HttpAsyncStreamingRequest();

  private:
    static int cli_callback(void *user, int evt, void *data, size_t length,
                            const struct cli_identity_t *cli);

    int on_head(int version, int status, h2o_iovec_t msg,
                const h2o_headers_t *headers);

    int on_body(void *buf, size_t len);

    int on_finish(const char *err);

    int on_fill_request_body(struct http_client_handle_t *clih);

    bool is_status_ok() const { return IsHttpStatusOk(meta_.status); }

    /**
     * @brief Judge whether the http request is finished
     * @return true when yes or else false
     */
    bool isRequestFinished() const;

  private:
    struct http_req_meta_t {
        struct cli_identity_t cli;
        int state;
        int version;
        int status;
        H2O_VECTOR(char) body;
        const char *network_error;
    };

    SpIClient http_client_;
    IHttpAsyncStreamingCallback *cb_;
    const bool streaming_;
    struct http_req_meta_t meta_;

  private:
    DISALLOW_COPY_AND_ASSIGN(HttpAsyncStreamingRequest);
};

using SpHttpAsyncStreamingRequest = foundation::sp<HttpAsyncStreamingRequest>;

inline SpHttpAsyncStreamingRequest
createSpHttpAsyncStreamingRequest(SpIClient &client,
                                  IHttpAsyncStreamingCallback *cb)
{
    RETURN_IF_NULL(client, NULL);
    return new HttpAsyncStreamingRequest(client, cb);
}

#endif

#endif /* __INCLUDE_HTTP_ASYNC_STREAMING_REQUEST_H__ */
