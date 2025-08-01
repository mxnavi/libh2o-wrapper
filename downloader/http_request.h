/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : http_request.h
 *   CREATE DATE : 2022-07-30
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_HTTP_REQUEST_H__
#define __INCLUDE_HTTP_REQUEST_H__

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
class HttpRequest : public IHttpRequest
{
  public:
    explicit HttpRequest(const SpIClient &cli, const h2o_token_t *token[],
                         size_t num_token);

    /**
     * @brief Do http request according to the input request param
     * @param req   [I] the input request info
     * @return SUCCESS when response code ok or else error
     */
    int DoHttpRequest(const struct http_client_req_t *req);

    /**
     * @brief Cancel the in flight http request
     * @return SUCCESS when success or else error
     */
    virtual int Cancel();

    /**
     * @brief Get response body
     * @return iovec of response body
     */
    inline h2o_iovec_t GetResponseBody() const
    {
        return (h2o_iovec_t){meta_.body.entries, meta_.body.size};
    }

    /**
     * @brief Get response header by the input token
     * @param token [I] the input token pointer, not null
     * @return response header when success or else null pointer
     */
    const h2o_header_t *GetResponseHeader(const h2o_token_t *token) const;

    /**
     * @brief Get error message
     * @return error message when has or else null pointer
     */
    virtual const char *GetErrorMessage() { return meta_.network_error; }

#ifndef IMAP_STD_SHARED_PTR
  protected:
#endif
    virtual ~HttpRequest();

  private:
    static int cli_callback(void *user, int evt, void *data, size_t length,
                            const struct cli_identity_t *cli);

    int on_head(int version, int status, h2o_iovec_t msg,
                const h2o_headers_t *headers);

    int on_body(void *buf, size_t len);

    int on_finish(const char *err);

    bool is_status_ok() const { return IsHttpStatusOk(meta_.status); }

  private:
    struct http_req_meta_t {
        struct cli_identity_t cli;
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

    SpIClient http_client_;
    struct http_req_meta_t meta_;

  private:
    DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};

#ifdef IMAP_STD_SHARED_PTR
using SpHttpRequest = std::shared_ptr<HttpRequest>;
#else
using SpHttpRequest = foundation::sp<HttpRequest>;
#endif

inline SpHttpRequest createSpHttpRequest(SpIClient &client,
                                         const h2o_token_t *token[],
                                         size_t num_token)
{
#ifdef IMAP_STD_SHARED_PTR
    return std::make_shared<HttpRequest>(client, token, num_token);
#else
    return new HttpRequest(client, token, num_token);
#endif
}

#endif

#endif /* __INCLUDE_HTTP_REQUEST_H__ */
