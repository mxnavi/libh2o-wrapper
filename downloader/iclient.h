/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : iclient.h
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_ICLIENT_H__
#define __INCLUDE_ICLIENT_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <stdlib.h>
#include <stdint.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Thread.h>
#include <stl_container.h>
#include <common_defines.h>
using namespace foundation;

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
/**
 * Client event
 */
#define CLI_EVT_HOSTRESOLVED 0x01
#define CLI_EVT_CONNECTED 0x02
#define CLI_EVT_WS_HANDSHAKED 0x04
#define CLI_EVT_HTTP_HEADER 0x08
#define CLI_EVT_HTTP_BODY 0x10
#define CLI_EVT_MSG 0x20
#define CLI_EVT_HTTP_FILL_REQ_BODY 0x40
#define CLI_EVT_CLOSED (-1)

#define CLI_INVALID_ID 0

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
/* Client identity */
struct cli_identity_t {
    uint32_t id;
};

/* Client callback */
typedef int (*cli_callback_t)(void * /* user */, int /* evt */,
                              void * /* data */, size_t /* length */,
                              const struct cli_identity_t * /* cli */);

/* Client request */
struct cli_req_t {
    void *user;
    cli_callback_t cb;
};

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
class IClient : public RefBase
{
  public:
    /**
     * Issue client request
     *
     * @param req super of input request param
     * @param cli output client handle cli
     * @return 0 when success or else error
     */
    virtual int DoRequest(const struct cli_req_t *req,
                          struct cli_identity_t *cli) = 0;

    /**
     * Cancel client request according to client handle
     * @param cli client handle
     * @return 0 when success or else error
     */
    virtual int Cancel(const struct cli_identity_t *cli) = 0;

    /**
     * Start a timer in client event loop thread
     * @param timedout      [I] timeout callback
     * @param param         [I] timeout callback param
     * @param timeout_ms    [I] timeout in milisecond
     * @param repoeat       [I] repeat flag
     * @return 0 when success or else error
     */
    virtual uint32_t StartTimer(void (*timedout)(void *param, uint32_t),
                                void *param, uint32_t timeout_ms,
                                bool repeat) = 0;

    /**
     * Stop the timer
     * @param tm            [I] timer created by start_timer
     * @return void
     */
    virtual void StopTimer(uint32_t tm) = 0;

    /**
     * @return true when in async mode or else false
     */
    inline bool IsAsync() const { return async_; }

  protected:
    /**
     * @param async async flag
     *
     * true: start() will **NOT** blocked waiting for connection ready
     * false: start() will **blocked** waiting for connection ready
     */
    explicit IClient(bool async) : async_(async) {}

    virtual ~IClient() {}

    static int call_cli_callback(struct cli_req_t *req, int32_t evt, void *data,
                                 size_t len, const struct cli_identity_t *cli)
    {
        if (req->cb != NULL) {
            return req->cb(req->user, evt, data, len, cli);
        }
        return 0;
    }

  private:
    const bool async_;
};

using SpIClient = foundation::sp<IClient>;

#endif

#endif /* __INCLUDE_ICLIENT_H__ */
