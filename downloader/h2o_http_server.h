/********** Copyright(C) 2023 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : h2o_http_client.h
 *   CREATE DATE : 2023-03-06
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_H2OHTTPSERVER_H__
#define __INCLUDE_H2OHTTPSERVER_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Thread.h>

#include <stl_container.h>
#include <common_defines.h>
using namespace foundation;

#include <libh2o_log.h>
#include <libh2o_http_server/libh2o_http_server.h>

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


class IHttpRequestListener
{
  public:
    /**
     * @brief Handle the incoming request
     * @return SUCCESS when success or else error
     */
    virtual void OnReq(struct http_request_t *data) = 0;
};

/**
 * @brief Http server event loop and request manager
 */
class H2oHttpServer : public RefBase
{
  public:
    explicit H2oHttpServer(const char *host, const char *port, const char *cer,
                           const char *key, IHttpRequestListener *l);

    uint32_t StartTimer(void (*timedout)(void *param, uint32_t), void *param,
                        uint32_t timeout_ms, bool repeat);

    void StopTimer(uint32_t tm);

  protected:
    virtual ~H2oHttpServer();

  private:
    void on_http_request(struct http_request_t *data);
    void on_http_resp_timeout(struct http_request_t *data);
    void on_finish_http_request(struct http_request_t *data);

  private:
    static void http_server_on_http_request_cb(void *param,
                                               struct http_request_t *data);

    static void
    http_server_on_http_resp_timeout_cb(void *param,
                                        struct http_request_t *data);

    static void
    http_server_on_finish_http_request_cb(void *param,
                                          struct http_request_t *data);

    static void
    http_server_on_ws_recv_cb(void *param, void *buf, size_t len,
                              const struct websocket_handle_t *clih);

    static void
    http_server_on_ws_sent_cb(void *param, void *buf, size_t len,
                              const struct websocket_handle_t *clih);

    static void
    http_server_on_ws_connected_cb(void *param,
                                   const struct websocket_handle_t *clih);

    static void http_server_on_ws_connection_closed_cb(
        void *param, const struct websocket_handle_t *clih);

  private:
    IHttpRequestListener *l_;
    struct server_context_t *server_ctx_;

  private:
    DISALLOW_COPY_AND_ASSIGN(H2oHttpServer);
};

using SpH2oHttpServer = foundation::sp<H2oHttpServer>;

inline SpH2oHttpServer createSpH2oHttpServer(const char *host, const char *port,
                                             const char *cer, const char *key,
                                             IHttpRequestListener *l)
{
    return new H2oHttpServer(host, port, cer, key, l);
}

#endif /* __INCLUDE_H2OHTTPSERVER_H__ */
