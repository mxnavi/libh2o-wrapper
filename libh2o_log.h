/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_log.h
 *   CREATE DATE : 2019-03-20
 *   MODULE      : libh2o_log
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef LOG_TAG
#define LOG_TAG "libh2o"
#endif

/****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <stdio.h>
#ifndef LIBH2O_MISSING_CUTILS_LOG
#include <cutils/log.h>
#endif

/****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#ifndef LOGV
#define LOGV(fmt, args...) ((void)0)
#endif

#ifndef LOGD
#define LOGD(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifndef LOGI
#define LOGI(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifndef LOGW
#define LOGW(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifndef LOGE
#define LOGE(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifndef ASSERT
#define ASSERT assert
#endif

/* clang-format off */
#define H2O_LOGV(fmt, args...) LOGV(fmt, ##args)
#if defined(ENABLE_TEST) || !defined(NDEBUG)
#define H2O_LOGD(fmt, args...) LOGD(fmt, ##args)
#else
#define H2O_LOGD(fmt, args...) LOGV(fmt, ##args)
#endif
#define H2O_LOGI(fmt, args...) LOGI(fmt, ##args)
#define H2O_LOGW(fmt, args...) LOGW(fmt, ##args)
#define H2O_LOGE(fmt, args...) LOGE(fmt, ##args)
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
void libh2o_error_printf(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

/****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/

/****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

/****************************************************************************
 *                       Functions Implement Section                         *
 *****************************************************************************/

#ifdef __cplusplus
}
#endif

