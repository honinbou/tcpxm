/***************************************************************************
 * 
 * Copyright (c) 2012 Xiaomi.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file log.c
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/09/16 20:30:41
 * @version $Revision$ 
 * @brief 
 *  
 **/

#include "log.h"

log4c_category_t* category = NULL;

int log_open()
{
	if (log4c_init() == 1)
	{
		return 1;
	}
	category = log4c_category_get(CATEGORY_NAME);
	return 0 ;
}

void log_message(int level, const char* format, ...) 
{
	va_list va;
	
	int priority = log4c_category_get_priority(category);
	if(level > priority)
	{
		return;
	}
	va_start(va, format);
	log4c_category_vlog(category, level, format, va);
	va_end(va);
	
}

int log_close()
{
	return(log4c_fini());
}



















/* vim: set ts=4 sw=4 sts=4 tw=100 noet: */
