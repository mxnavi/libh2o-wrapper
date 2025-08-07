/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : http_async_request.h
 *   CREATE DATE : 2022-10-13
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_HTTP_ASYNC_REQUEST_H__
#define __INCLUDE_HTTP_ASYNC_REQUEST_H__

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

/**
 * @brief Represents a http request
 */
class HttpAsyncRequest : public IHttpRequest
{
  public:
    explicit HttpAsyncRequest(const SpIClient &cli, const h2o_token_t *token[],
                              size_t num_token);

    /**
     * @brief Do http request according to the input request param
     * @param req   [I] the input request info
     * @return SUCCESS when success or else error
     */
    int DoHttpAsyncRequest(const struct http_client_req_t *req);

    /**
     * @brief Wait the request finish
     * @return SUCCESS when http status code is ok or else error
     * @note this function blocks the caller until the request finished
     */
    int Wait();

    /**
     * @brief Cancel the in flight http request
     * @return SUCCESS when success or else error
     */
    virtual int Cancel();

    /**
     * @brief Judge whether the http request is finished
     * @return true when yes or else false
     * @note this function does not block the caller
     */
    bool IsRequestFinished() const;

    /**
     * @brief Judge whether the http status code is 200 OK
     * @return true when yes or else false
     * @note this function blocks the caller until the request finished
     */
    bool IsHttpStatusOK();

    /**
     * @brief Get response body
     * @return iovec of response body
     * @note this function blocks the caller until the request finished
     */
    h2o_iovec_t GetResponseBody();

    /**
     * @brief Get response header by the input token
     * @param token [I] the input token pointer, not null
     * @return response header when success or else null pointer
     */
    const h2o_header_t *GetResponseHeader(const h2o_token_t *token);

    /**
     * @brief Get error message
     * @return error message when has or else null pointer
     */
    virtual const char *GetErrorMessage();

    /* helpers */
    /**
     * @brief Do async http request and wait finish
     */
    inline int DoHttpRequest(const struct http_client_req_t *req)
    {
        int rc = DoHttpAsyncRequest(req);
        RETURN_IF_FAIL(rc, rc);
        return Wait();
    }

  protected:
    virtual ~HttpAsyncRequest();

  private:
    static int cli_callback(void *user, int evt, void *data, size_t length,
                            const struct cli_identity_t *cli);

    int on_head(int version, int status, h2o_iovec_t msg,
                const h2o_headers_t *headers);

    int on_body(void *buf, size_t len);

    int on_finish(const char *err);

    void assure_request_finished();

    bool is_status_ok() const { return IsHttpStatusOk(meta_.status); }

  private:
    struct http_req_meta_t {
        struct cli_identity_t cli;
        int state;
        int version;
        int status;
        const h2o_token_t *tokens[4];
        h2o_headers_t headers;
        H2O_VECTOR(char) body;
        const char *network_error;
#ifdef ENABLE_TEST
        uint8_t content_type_text; /* show response body when text */
#endif
    };

    mutable Mutex mutex_;
    Condition cond_;
    SpIClient http_client_;
    struct http_req_meta_t meta_;

  private:
    DISALLOW_COPY_AND_ASSIGN(HttpAsyncRequest);
};

using SpHttpAsyncRequest = foundation::sp<HttpAsyncRequest>;

inline SpHttpAsyncRequest createSpHttpAsyncRequest(SpIClient &client,
                                                   const h2o_token_t *token[],
                                                   size_t num_token)
{
    RETURN_IF_NULL(client, NULL);
    return new HttpAsyncRequest(client, token, num_token);
}

#endif

#endif /* __INCLUDE_HTTP_ASYNC_REQUEST_H__ */
