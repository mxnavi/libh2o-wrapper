/********** Copyright(C) 2018 MXNavi Co.,Ltd. ALL RIGHTS RESERVED **********/
/****************************************************************************
 *   FILE NAME   : libh2o_cmn.h
 *   CREATE DATE : 2019-04-04
 *   MODULE      : libh2o
 *   AUTHOR      : chenbd
 *---------------------------------------------------------------------------*
 *   MEMO        :
 *****************************************************************************/

/*****************************************************************************
 *                       Include File Section                                *
 *****************************************************************************/

/*****************************************************************************
 *                       Macro Definition Section                            *
 *****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                       Type Definition Section                             *
 *****************************************************************************/
int libh2o_ssl_init();
void libh2o_signal_init();

void libh2o_show_socket_err(const char *prefix, int fd);

/*****************************************************************************
 *                       Global Variables Section                            *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Prototype Section                         *
 *****************************************************************************/

/*****************************************************************************
 *                       Functions Implement Section                         *
 *****************************************************************************/

#ifdef __cplusplus
}
#endif

