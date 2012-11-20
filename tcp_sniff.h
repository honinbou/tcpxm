/***************************************************************************
 * 
 * Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file tcp_sniff.h
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/11/10 23:16:52
 * @version $Revision$ 
 * @brief test_sniff file
 *  
 **/

#ifndef  __TCP_SNIFF_H_
#define  __TCP_SNIFF_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <string.h>
#include <sys/time.h>
#include <ctype.h>

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <netdb.h>

#include <libconfig.h>

#include "log.h"
#include "tcp.h"
#include "ip.h"
#include "ether.h"
#include "queue.h" 

#define ETHER_HDRLEN 14
#define TSEQ_HASHSIZE 919

/* Tcp status struct */
struct tcp_status
{
	char user[16];
	struct timeval t0;
	struct timeval t1;
	struct timeval t2;
	struct timeval t3;
	struct timeval t4;
	struct timeval t5;
	struct timeval t6;
	struct timeval t7;
	uint32_t succ_ack;
};

/* Tcp hash table key, no support ipv6 */
struct tha {
	struct in_addr src;
	struct in_addr dst;
	u_int port;
};

struct tcp_status_queue {
	/* The result of tcp data */
	struct tha addr;
	struct tcp_status status;
	/* For the linked list structure. */
	TAILQ_ENTRY(tcp_status_queue) entries;
};


/* Tcp hash table value, no support ipv6 */
struct tcp_seq_hash {
	struct tcp_seq_hash *nxt;
	struct tha addr;
	tcp_seq seq;
	tcp_seq ack;
	struct tcp_status status;
};







#endif  //__TCP_SNIFF_H_

/* vim: set ts=4 sw=4 sts=4 tw=100 noet: */
