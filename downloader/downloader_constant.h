/********** Copyright(C) 2025 MXNavi Co.,Ltd. ALL RIGHTS RESERVED ***********/
/****************************************************************************
 *   FILE NAME   : downloader_constant.h
 *   CREATE DATE : 2025-08-11
 *   MODULE      : EHP
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/
#ifndef __INCLUDE_DOWNLOADER_CONSTANT_H__
#define __INCLUDE_DOWNLOADER_CONSTANT_H__

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/
#include <sys/cdefs.h>

__BEGIN_DECLS

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/
/* max length of etag for http downloader */
#define __HTTP_ETAG_MAXLEN (34 /* hexstring(md5()) */ + 1)

/* coding */
#define __CODING_INVALID 0
#define __CODING_GZIP 1
#define __CODING_ZLIB 2
#define __CODING_AUTO 3
#define __CODING_LZ4 4
#define __CODING_NONE 5

#define IS_VALID_CODING(coding)                                                \
    (((coding) > __CODING_INVALID) && ((coding) <= __CODING_NONE))

#define IS_VALID_NOT_NONE_CODING(coding)                                       \
    (IS_VALID_CODING(coding) && ((coding) != __CODING_NONE))

/* default coding */
#ifndef __CODING_DEFAULT
#define __CODING_DEFAULT __CODING_ZLIB
#endif

/**
 * The max-age=N response directive indicates that the response remains fresh
 * until N seconds after the response is generated.
 */
#define __MAX_AGE_DEFAULT (3600 * 24 * 7)
#define __MAX_AGE_RETRY_AFTER (180)

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/

/*****************************************************************************
 *                       Global Variables Prototype Section                  *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/


__END_DECLS

#endif /* __INCLUDE_DOWNLOADER_CONSTANT_H__ */
