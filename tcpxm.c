/***************************************************************************
 * 
 * Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file tcpxm.c
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/11/10 23:05:00
 * @version $Revision$ 
 * @brief 
 *  
 **/

#include <stdio.h>
#include <libconfig.h>
#include "log.h" 

extern char dev[16];
extern char filter_exp[1024];
extern int packetnum;
extern int debug;
extern int MTU;

void* tcpsnifffunc(void* arg)
{
	LOG_INFO("tcp sniff thread begin:\n");
	tcp_sniff();
	return NULL;
}

void* tcpdump2file()
{
	LOG_INFO("tcp result dump 2 file");
	dump2file();
	return NULL;
}

int parse_config(char* file)
{
	config_t cfg;
	config_init(&cfg);

	/* Read the config file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, file))
	{
		goto err;
	}
	const char* p = NULL;
	int ret = config_lookup_string(&cfg, "tcpxm.dev", &p);
	if(ret == CONFIG_FALSE)
	{
		goto err;
	}
	memcpy(dev, p, strlen(p));
	dev[strlen(p)] = '\0';
	LOG_DEBUG("net dev: %s", dev);

	ret = config_lookup_string(&cfg, "tcpxm.filter_exp", &p);
	if(ret == CONFIG_FALSE)
	{
		goto err;
	}
	memcpy(filter_exp, p, strlen(p));
	dev[strlen(p)] = '\0';
	LOG_DEBUG("filter exp: %s", filter_exp);

	ret = config_lookup_int(&cfg, "tcpxm.packetnum", &packetnum);
	if(ret == CONFIG_FALSE)
	{
		goto err;
	}
	LOG_DEBUG("sniff packet num: %d", packetnum);

	ret = config_lookup_int(&cfg, "tcpxm.debug", &debug);
	if(ret == CONFIG_FALSE)
	{
		goto err;
	}
	LOG_DEBUG("debug mode: %d", debug);

	ret = config_lookup_int(&cfg, "tcpxm.MTU", &MTU);
	if(ret == CONFIG_FALSE)
	{
		goto err;
	}
	LOG_DEBUG("debug mode: %d", debug);


	config_destroy(&cfg);
	return(EXIT_SUCCESS);

err:
	printf("%s:%d - %s\n", config_error_file(&cfg),config_error_line(&cfg), config_error_text(&cfg));
	config_destroy(&cfg);
	return(EXIT_FAILURE);

}

int main(int argc, char const *argv[])
{
    if ( log_open() == 1 ) 
    {   
        printf("log_open failed!\n");
		return -1;
    } 

	int ret = parse_config("conf/tcpxm.conf");
	if(ret != EXIT_SUCCESS)
	{
		LOG_ERROR("config read error.");
		return -1;
	}

	pthread_t tcpsniffid, tcpdumpid;
	pthread_create(&tcpsniffid, NULL, tcpsnifffunc, NULL);
	pthread_create(&tcpdumpid, NULL, tcpdump2file, NULL);
	pthread_join(tcpsniffid, NULL);
	pthread_join(tcpdumpid, NULL);

    if(log_close() == 1)
    {   
        printf("log_close() failed!\n");
    }   

}




















/* vim: set ts=4 sw=4 sts=4 tw=100 noet: */
