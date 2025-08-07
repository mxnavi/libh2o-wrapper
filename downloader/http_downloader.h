/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : http_downloader.h
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_HTTP_DOWNLOADER_H__
#define __INCLUDE_HTTP_DOWNLOADER_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "h2o_http_client.h"
#include "idownloader.h"

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
 * @brief File downloader over http
 */
class HttpDownloader : public IDownloader
{
  public:
    explicit HttpDownloader(const SpIClient &cli);

    virtual int DownloadFile(const struct dl_meta_t *m);
    virtual const struct dl_meta_t *GetMeta(int *fd);
    virtual int GetFd() override;
    virtual int CheckFd() const override;
    virtual int Cancel();

  protected:
    virtual ~HttpDownloader();

  private:
    static int cli_callback(void *user, int evt, void *data, size_t length,
                            const struct cli_identity_t *cli);

    int on_head(int version, int status, h2o_iovec_t msg,
                const h2o_headers_t *headers);

    int on_body(void *buf, size_t len);

    int on_finish(const char *err);

  private:
    struct http_dl_meta_t {
        struct dl_meta_t super;
        int fd;
        int state;
        uint8_t chunked;
        size_t notify_range;
        size_t notify_size;
        int64_t notify_time;
        struct cli_identity_t cli;
    };

    SpIClient http_client_;
    struct http_dl_meta_t meta_;

  private:
    DISALLOW_COPY_AND_ASSIGN(HttpDownloader);
};

inline SpIDownloader createSpHttpDownloader(SpIClient &client)
{
    return new HttpDownloader(client);
}

/* helpers */
inline bool isHttpStatusOk(const struct dl_meta_t *meta)
{
    return IsHttpStatusOk(meta->http.status);
}
inline bool isHttpStatusNoContent(const struct dl_meta_t *meta)
{
    return IsHttpStatusNoContent(meta->http.status);
}
inline bool isHttpStatusOkOrPartialContent(const struct dl_meta_t *meta)
{
    return IsHttpStatusOkOrPartialContent(meta->http.status);
}
inline bool isHttpStatusMovedPermanently(const struct dl_meta_t *meta)
{
    return IsHttpStatusMovedPermanently(meta->http.status);
}
inline bool isHttpStatusNotModified(const struct dl_meta_t *meta)
{
    return IsHttpStatusNotModified(meta->http.status);
}
inline bool isHttpStatusInformational(const struct dl_meta_t *meta)
{
    return IsHttpStatusInformational(meta->http.status);
}
inline bool isHttpStatusSuccessful(const struct dl_meta_t *meta)
{
    return IsHttpStatusSuccessful(meta->http.status);
}
inline bool isHttpStatusRedirection(const struct dl_meta_t *meta)
{
    return IsHttpStatusRedirection(meta->http.status);
}
inline bool isHttpStatusClientError(const struct dl_meta_t *meta)
{
    return IsHttpStatusClientError(meta->http.status);
}
inline bool isHttpStatusNotFound(const struct dl_meta_t *meta)
{
    return IsHttpStatusNotFound(meta->http.status);
}
inline bool isHttpStatusServerError(const struct dl_meta_t *meta)
{
    return IsHttpStatusServerError(meta->http.status);
}

#endif

#endif /* __INCLUDE_HTTP_DOWNLOADER_H__*/
