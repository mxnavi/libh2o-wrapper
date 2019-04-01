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
#ifdef PLATFORM_SDK_VERSION
#include <cutils/log.h>
#elif defined(__ANDROID__)
#include <android/log.h>
#define ALOGV(fmt, args...)                                                    \
    __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, fmt, ##args)
#define ALOGD(fmt, args...)                                                    \
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define ALOGI(fmt, args...)                                                    \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)
#define ALOGW(fmt, args...)                                                    \
    __android_log_print(ANDROID_LOG_WARN, LOG_TAG, fmt, ##args)
#define ALOGE(fmt, args...)                                                    \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)
#else
#endif
/****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
#ifdef ALOGV
#define LOGV ALOGV
#else
#define LOGV(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifdef ALOGD
#define LOGD ALOGD
#else
#define LOGD(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifdef ALOGI
#define LOGI ALOGI
#else
#define LOGI(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifdef ALOGW
#define LOGW ALOGW
#else
#define LOGW(fmt, args...) ((void)fprintf(stderr, fmt "\n", ##args))
#endif

#ifdef ALOGE
#define LOGE ALOGE
#else
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

