/***************************************************************************
 * 
 * Copyright (c) 2012 Xiaomi.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file log.h
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/09/16 19:37:37
 * @version $Revision$ 
 * @brief 
 *  
 **/


#ifndef  __LOG_H_
#define  __LOG_H_

#include <string.h>
#include <stdlib.h>
#include "log4c.h"
#define CATEGORY_NAME "tcpxm"

//1.LOG4C_PRIORITY_ERROR
//2.LOG4C_PRIORITY_WARN
//3.LOG4C_PRIORITY_NOTICE
//4.LOG4C_PRIORITY_DEBUG
//5.LOG4C_PRIORITY_TRACE

int log_open();
void log_message(int level, const char* format, ...);
int log_close();

#define LOG_ERROR(fmt, arg...) do { \
	    log_message(LOG4C_PRIORITY_ERROR, "[%s:%d][FUNC:%s] " fmt,\
				        __FILE__, __LINE__, __FUNCTION__, ## arg); \
}while (0)

#define LOG_WARN(fmt, arg...) do { \
	    log_message(LOG4C_PRIORITY_WARN, "[%s:%d][FUNC:%s] " fmt,\
				        __FILE__, __LINE__, __FUNCTION__, ## arg); \
}while (0)

#define LOG_NOTICE(fmt, arg...) do { \
	    log_message(LOG4C_PRIORITY_NOTICE, "[%s:%d][FUNC:%s] " fmt,\
				        __FILE__, __LINE__, __FUNCTION__, ## arg); \
}while (0)

#define LOG_INFO(fmt, arg...) do { \
	    log_message(LOG4C_PRIORITY_INFO, "[%s:%d][FUNC:%s] " fmt,\
				        __FILE__, __LINE__, __FUNCTION__, ## arg); \
}while (0)

#define LOG_DEBUG(fmt, arg...) do { \
	    log_message(LOG4C_PRIORITY_DEBUG, "[%s:%d][FUNC:%s] " fmt,\
				        __FILE__, __LINE__, __FUNCTION__, ## arg); \
}while (0)














#endif  //__LOG_H_

/* vim: set ts=4 sw=4 sts=4 tw=100 noet: */
