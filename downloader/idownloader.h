/********** Copyright(C) 2022 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/*****************************************************************************
 *   FILE NAME   : idownloader.h
 *   CREATE DATE : 2022-07-14
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_IDOWNLOADER_H__
#define __INCLUDE_IDOWNLOADER_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include "downloader_constant.h"
#include "h2o_http_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
/**
 * Downloader event
 */
#define DL_EVT_START 0x01
#define DL_EVT_PROGRESS 0x02
#define DL_EVT_FINISH 0x04
#define DL_EVT_ERROR (-1)

#define validate_fixup_dl_meta(m)                                              \
    do {                                                                       \
        if (m->range > 0) {                                                    \
            struct stat sb;                                                    \
            if (stat(m->save_path, &sb) == -1) {                               \
                H2O_LOGW("stat(%s) error: %s, force 0 range", m->save_path,   \
                          strerror(errno));                                    \
                m->range = 0;                                                  \
            } else if (sb.st_size < m->range) {                                \
                H2O_LOGW("invalid range: %zu, force 0 range", m->range);      \
                m->range = 0;                                                  \
            }                                                                  \
        }                                                                      \
    } while (0)


/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
struct dl_meta_t;
class IDownloader;

/**
 * return 0 when success or else error
 */
typedef int (*dl_cb_t)(void *, const struct dl_meta_t *, int, IDownloader *);

struct dl_meta_t {
    dl_cb_t cb;  /* download call back */
    void *param; /* download call back param */
    size_t range;        /* start range for particial download */
    size_t len;          /* total download file length in bytes */
    char url[256];       /* download url */
    char save_path[256]; /* download file saving path */
    union {
        struct {
            uint8_t want_etag : 1;
            uint8_t want_encoding : 1;
            uint8_t want_cache_control : 1;
            uint8_t want_speed : 1;
            uint8_t coding;   /* for http Content-Encoding header */
            uint32_t speed;   /* Speed in KB/s */
            int32_t status;   /* status code */
            uint32_t max_age; /* for http Cache-Control header */
            char etag[__HTTP_ETAG_MAXLEN]; /* for http ETag header */
            const char *method; /* const string, if NULL, default is 'GET' */
            struct http_request_header_t
                header[3];      /* optional request header */
            h2o_iovec_t body;   /* optional request body */
        } http;
    };
    const char *network_error; /* netwrok error when not NULL */
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
/**
 * @brief File downloader interface
 */
class IDownloader : public RefBase
{
  public:
    IDownloader() {}

    /**
     * return 0 when success or else error
     */
    virtual int DownloadFile(const struct dl_meta_t *m) = 0;

    /**
     * Get meta data and optional fd (owner transfers to caller)
     */
    virtual const struct dl_meta_t *GetMeta(int *fd) = 0;
    /**
     * Get fd for downloaded file, the owner transfers to caller
     */
    virtual int GetFd() = 0;

    /**
     * Get fd for downloaded file, no owner transfer
     */
    virtual int CheckFd() const = 0;

    virtual int Cancel() = 0;

  protected:
    virtual ~IDownloader() {}

    int call_dl_cb(struct dl_meta_t *meta, int evt)
    {
        if (meta->cb) {
            return meta->cb(meta->param, meta, evt, this);
        }
        return 0;
    }

    static bool is_dl_ok(const struct dl_meta_t *meta)
    {
        if (meta->len == 0 || meta->len == SIZE_MAX) {
            return false;
        } else if (meta->len != meta->range) {
            return false;
        }
        return true;
    }
};

using SpIDownloader = foundation::sp<IDownloader>;

#endif

#endif /* __INCLUDE_IDOWNLOADER_H__ */
