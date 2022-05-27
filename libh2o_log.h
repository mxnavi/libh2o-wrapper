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
#include <cutils/log.h>

/****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#ifndef LOGV
#define LOGV(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
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

