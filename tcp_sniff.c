/***************************************************************************
 * 
 * Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file tcp_sniff.c
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/11/10 23:16:38
 * @version $Revision$ 
 * @brief tcp sniff file
 *  
 **/
#include "tcp_sniff.h"

char dev[16]={'\0'};
char filter_exp[1024];
int packetnum;
int debug;
int MTU;

/*This hash Map contain all the tcp connect status */
static struct tcp_seq_hash tcp_seq_hash[TSEQ_HASHSIZE]; 

TAILQ_HEAD(, tcp_status_queue) status_queue;

void print_packet(u_char* args, const struct pcap_pkthdr* header, const struct ip* ip, const struct tcphdr* tcp)
{
	//larger than MTU
	int bufsize = MTU+1024;
	char *buf = (char *)malloc(bufsize);

	buf[0] = '\0';

	//print time
	struct timeval ts;
	ts.tv_sec = header->ts.tv_sec;
	ts.tv_usec = header->ts.tv_usec;
	struct tm *_tm = localtime(&(ts.tv_sec));
	char timestr[20]={'\0'};
	memset(timestr, '\0', 20);
	strftime(timestr, 20, "%H:%M:%S", _tm);
	snprintf(buf, bufsize, "%s.%ld ", timestr, ts.tv_usec);

	char sbuf[20];
	char dbuf[20];
	snprintf(sbuf, 20, "%s", inet_ntoa(ip->ip_src));
	snprintf(dbuf, 20, "%s", inet_ntoa(ip->ip_dst));


	//print src_addr, src_port, dst_addr, dst_port
	snprintf(buf+strlen(buf), bufsize, "IP: %s.%u > %s.%u ", 
		sbuf, ntohs(tcp->th_sport), 
		dbuf, ntohs(tcp->th_dport));

	//print version, header_len, tos, total_len, id, flags, fragment_offset,
	//ttl, protocol, checksum
	snprintf(buf+strlen(buf), bufsize, "version:%u, header_len:%u, tos:%u, total_len:%u, id:%u, flags:%u, fragment_offset:%u, ttl:%u, protocol:%u, checksum:%u", 
		IP_V(ip), IP_HL(ip), ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id),
		~(ip->ip_off ^ 0x1fff) >> 13, ntohs(ip->ip_off & 0x1fff), ip->ip_ttl, 
		ip->ip_p, ntohs(ip->ip_sum));

	//print seq, ack, tcp_header_len, tcp_bit, win, sum, urp
	snprintf(buf+strlen(buf), bufsize, " seq:%u, ack:%u, tcp_header_len:%u, tcp_bit:%u, win:%u, sum:%u, urp:%u",
		htonl(tcp->th_seq), htonl(tcp->th_ack), (tcp->th_offx2 & 0xf0) >> 4,
		(tcp->th_flags & 0x3f), ntohs(tcp->th_win), ntohs(tcp->th_sum),
		ntohs(tcp->th_urp));

	//tcp_data
	int ip_len = ntohs(ip->ip_len);
	int ip_header_len = IP_HL(ip)*4;
	int tcp_header_len = TH_OFF(tcp)*4;
	int tcp_data_len = (ip_len - ip_header_len - tcp_header_len);
	if (tcp_data_len !=  0)
	{
		char *tcp_buf = (char *)malloc(tcp_data_len+1);
		memcpy(tcp_buf, (void *)tcp+tcp_header_len, tcp_data_len);
		tcp_buf[tcp_data_len]='\0';

		snprintf(buf+strlen(buf), bufsize, " tcp_data:\n%s",tcp_buf);
		free(tcp_buf); tcp_buf = NULL;
	}

	buf[strlen(buf)] = '\0';
//	printf("%s\n", buf);
	LOG_DEBUG("%s", buf);
	free(buf); buf = NULL;

}

void dump2file()
{
	while(1)
	{
		int flag = TAILQ_EMPTY(&status_queue);
		if (!flag)
		{
			struct tcp_status_queue *outputq;
			outputq = TAILQ_FIRST(&status_queue);
			struct tha addr = outputq->addr;
			struct tcp_status status = outputq->status;
			struct in_addr src = addr.src;
			struct in_addr dst = addr.dst;
			uint16_t sport = addr.port >> 16;
			uint16_t dport = addr.port & 0xffff;
	
			struct timeval rtt, login;
			if (status.t2.tv_usec < status.t1.tv_usec )
			{
				rtt.tv_sec = status.t2.tv_sec - status.t1.tv_sec - 1;
				rtt.tv_usec = 1000000 + status.t2.tv_usec - status.t1.tv_usec;
					
			}else{
				rtt.tv_sec = status.t2.tv_sec - status.t1.tv_sec;
				rtt.tv_usec = status.t2.tv_usec - status.t1.tv_usec;
			}
			login.tv_sec = status.t6.tv_sec + rtt.tv_sec;
			login.tv_usec = status.t6.tv_usec + rtt.tv_usec;

			//must first put data here, or the dst ip == src ip,
			//I don't know why
			char sbuf[20];
			char dbuf[20];
			snprintf(sbuf, 20, "%s", inet_ntoa(src));
			snprintf(dbuf, 20, "%s", inet_ntoa(dst));

			char tmp_str[1024];
	        snprintf(tmp_str, 1024, "%d.%d, %s.%d->%s.%d [usr:%s] [login:%f] [t1:%f] [rtt:%f] [t3:%f] [t4:%f] [t5:%f] [t6:%f] [t7:%f]",
	        	status.t0.tv_sec, status.t0.tv_usec, sbuf, sport, 
	        	dbuf, dport, status.user,
	        	(float)(login.tv_sec*1000+login.tv_usec*1.0/1000), (float)(status.t1.tv_sec*1000+status.t1.tv_usec*1.0/1000), 
	        	(float)(rtt.tv_sec*1000+rtt.tv_usec*1.0/1000), (float)(status.t3.tv_sec*1000+status.t3.tv_usec*1.0/1000),
	        	(float)(status.t4.tv_sec*1000+status.t4.tv_usec*1.0/1000), (float)(status.t5.tv_sec*1000+status.t5.tv_usec*1.0/1000),
	        	(float)(status.t6.tv_sec*1000+status.t6.tv_usec*1.0/1000), (float)(status.t7.tv_sec*1000+status.t7.tv_usec*1.0/1000)
	        	);

			printf("%s\n", tmp_str);
			LOG_NOTICE("%s", tmp_str);

			//remove itme
			TAILQ_REMOVE(&status_queue, outputq, entries);
			free(outputq);
		}else{
			usleep(500);
		}
	}
}

int is_set(u_char bit, u_char flag )
{
	return bit & flag;
}

void store_packet(u_char *args, const struct pcap_pkthdr *header, const struct ip *ip, const struct tcphdr *tcp)
{
	print_packet(args, header, ip, tcp);

	struct tcp_seq_hash *th;
	struct timeval ts;
	void *src, *dst;
	u_int16_t sport, dport;
	u_int32_t seq, ack;
	int rev;
	struct tha tha;

	src = &ip->ip_src;
	dst = &ip->ip_dst;
	seq = htonl(tcp->th_seq);
	ack = htonl(tcp->th_ack);
	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);
	ts.tv_sec = header->ts.tv_sec;
	ts.tv_usec = header->ts.tv_usec;

	u_char tcp_bit = tcp->th_flags & 0x3f;

	//LOG_DEBUG("tcp_bit: %0x\n", tcp_bit);
    //T1: SYN and ACK means that the flow is a server -> client flow
    if (is_set(tcp_bit, TH_SYN) && is_set(tcp_bit, TH_ACK))
    {
    	memcpy(&tha.src, dst, sizeof(ip->ip_dst));
		memcpy(&tha.dst, src, sizeof(ip->ip_src));
		tha.port = dport << 16 | sport;

		for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
			th->nxt; th = th->nxt)
		{
			if (memcmp((char *)&tha, (char *)&th->addr, sizeof(th->addr)) == 0)
			{
				break;
			}
		}

		if (th->nxt && th->seq + 1 == ack )
		{
			if (ts.tv_usec < th->status.t0.tv_usec )
			{
				th->status.t1.tv_sec = 1000000 + ts.tv_sec - th->status.t0.tv_sec;
				th->status.t1.tv_usec = ts.tv_usec - th->status.t0.tv_usec - 1;
				
			}else{
				th->status.t1.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
				th->status.t1.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
				
			}
			th->seq = seq;
			th->ack = ack;
			LOG_INFO("T1: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);
		}
    }
	//T0: SYN means that the flow is a client -> server flow
	else if (is_set(tcp_bit, TH_SYN))
	{
    	memcpy(&tha.dst, dst, sizeof(ip->ip_dst));
		memcpy(&tha.src, src, sizeof(ip->ip_src));
		tha.port = sport << 16 | dport;
	
		for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
				th->nxt; th = th->nxt)
		{
			if (memcmp((char *)&tha, (char *)&th->addr,
						sizeof(th->addr)) == 0)
			{
				break;
			}
		}

		/* didn't find it or new conversation */
		if (th->nxt == NULL) {
			th->nxt = (struct tcp_seq_hash *)
				calloc(1, sizeof(*th));
			if (th->nxt == NULL)
				LOG_ERROR("tcp_print: calloc");
			th->nxt->nxt = NULL;
		}
		th->addr = tha;
		th->seq = seq;
		th->ack = ack;
		th->status.t0.tv_sec = ts.tv_sec;
		th->status.t0.tv_usec = ts.tv_usec;
		LOG_INFO("T0: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);
		
	}
    else if (is_set(tcp_bit, TH_ACK) && ! is_set(tcp_bit, TH_PUSH | TH_FIN | TH_RST))
	{		
		memcpy(&tha.dst, dst, sizeof(ip->ip_dst));
		memcpy(&tha.src, src, sizeof(ip->ip_src));
		tha.port = sport << 16 | dport;
		
		for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
			th->nxt; th = th->nxt)
		{
			if (memcmp((char *)&tha, (char *)&th->addr, sizeof(th->addr)) == 0)
			{
				break;
			}
		}

		//No found previous packet
		if (th->nxt != NULL)
		{
			//T2: ACK means that the flow is TCP 3 times handshake finished.
			if (th->seq + 1 == ack )
			{
				if (ts.tv_usec < th->status.t0.tv_usec )
				{
					th->status.t2.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
					th->status.t2.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
					
				}else{
					th->status.t2.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
					th->status.t2.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
					
				}
				th->seq = seq;
				th->ack = ack;
				LOG_INFO("T2: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);
			}
			//client answer login success, send ack flow
			else if(th->status.succ_ack == seq)
			{
				if (ts.tv_usec < th->status.t0.tv_usec )
				{
					th->status.t7.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
					th->status.t7.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
					
				}else{
					th->status.t7.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
					th->status.t7.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
					
				}
				LOG_INFO("T7: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);

				struct timeval rtt, login;
				if (th->status.t2.tv_usec < th->status.t1.tv_usec )
				{
					rtt.tv_sec = th->status.t2.tv_sec - th->status.t1.tv_sec - 1;
					rtt.tv_usec = 1000000 + th->status.t2.tv_usec - th->status.t1.tv_usec;
					
				}else{

					rtt.tv_sec = th->status.t2.tv_sec - th->status.t1.tv_sec;
					rtt.tv_usec = th->status.t2.tv_usec - th->status.t1.tv_usec;
				}
				login.tv_sec = th->status.t6.tv_sec + rtt.tv_sec;
				login.tv_usec = th->status.t6.tv_usec + rtt.tv_usec;

				/*
				char tmp_str[1024];
	            snprintf(tmp_str, 1024, "%d.%d, %s.%d->%s.%d [usr:%s] [login:%f] [t1:%f] [rtt:%f] [t3:%f] [t4:%f] [t5:%f] [t6:%f] [t7:%f]",
	            	th->status.t0.tv_sec, th->status.t0.tv_usec, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), 
	            	inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport), th->status.user,
	            	(float)(login.tv_sec*1000+login.tv_usec*1.0/1000), (float)(th->status.t1.tv_sec*1000+th->status.t1.tv_usec*1.0/1000), 
	            	(float)(rtt.tv_sec*1000+rtt.tv_usec*1.0/1000), (float)(th->status.t3.tv_sec*1000+th->status.t3.tv_usec*1.0/1000),
	            	(float)(th->status.t4.tv_sec*1000+th->status.t4.tv_usec*1.0/1000), (float)(th->status.t5.tv_sec*1000+th->status.t5.tv_usec*1.0/1000),
	            	(float)(th->status.t6.tv_sec*1000+th->status.t6.tv_usec*1.0/1000), (float)(th->status.t7.tv_sec*1000+th->status.t7.tv_usec*1.0/1000)
	            	);

				LOG_DEBUG("%s", tmp_str);
				*/
				struct tcp_status_queue *inputq;
				inputq = (struct tcp_status_queue* )calloc(1, sizeof(struct tcp_status_queue));

				memcpy((void *)&(inputq->addr), (void *)&(tha), sizeof(tha));
				memcpy((void *)&(inputq->status), (void *)&(th->status), sizeof(th->status));

				TAILQ_INSERT_TAIL(&status_queue, inputq, entries);

			}

		}else{
			memcpy(&tha.src, dst, sizeof ip->ip_dst);
			memcpy(&tha.dst, src, sizeof ip->ip_src);
			tha.port = dport << 16 | sport;
	
			for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
				th->nxt; th = th->nxt)
			{
				if (memcmp((char *)&tha, (char *)&th->addr,
						sizeof(th->addr)) == 0)
				{
					break;
				}
			}
			//No found previous packet
			if (th->nxt == NULL)
			{
				LOG_WARN("No previous packet, drop this packet");
				return;
			}
	        //T4: after client first send push flow, server answer ACK
			if(th->ack == seq)
			{
				if (ts.tv_usec < th->status.t0.tv_usec )
				{
					th->status.t4.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
					th->status.t4.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
					
				}else{
					th->status.t4.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
					th->status.t4.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
					
				}
				th->seq = seq;
				th->ack = ack;
				LOG_INFO("T4: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);
			}			
		}
	
	}else if (is_set(tcp_bit, TH_PUSH))
	{		
		memcpy(&tha.dst, dst, sizeof(ip->ip_dst));
		memcpy(&tha.src, src, sizeof(ip->ip_src));
		tha.port = sport << 16 | dport;

		for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
			th->nxt; th = th->nxt)
		{
			if (memcmp((char *)&tha, (char *)&th->addr,
					sizeof(th->addr)) == 0)
			{
				break;
			}
		}
		//No found previous packet
		if (th->nxt != NULL)
		{
			//T3: after 3 times handshake, client first send push flow.
			if (th->seq == seq)
			{
				if (ts.tv_usec < th->status.t0.tv_usec )
				{
					th->status.t3.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
					th->status.t3.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
					
				}else{
					th->status.t3.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
					th->status.t3.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
					
				}
				LOG_DEBUG("T3: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);

				//tcp_data
				int ip_len = ntohs(ip->ip_len);
				int ip_header_len = IP_HL(ip)*4;
				int tcp_header_len = TH_OFF(tcp)*4;
				int tcp_data_len = (ip_len - ip_header_len - tcp_header_len);
				if (tcp_data_len !=  0)
				{
					char *tcp_buf = (char *)malloc(tcp_data_len+1);
					memcpy(tcp_buf, (void *)tcp+tcp_header_len, tcp_data_len);
					tcp_buf[tcp_data_len]='\0';

					char *p = NULL;
					if (debug)
					{
						p = strstr(tcp_buf, "Accept");
						if (p != NULL)
						{
							memcpy(th->status.user, "Accept", strlen("Accept"));
							th->status.user[strlen(th->status.user)] = '\0';
						}
					}else{
						p = strstr(tcp_buf, "id=");
						if (p != NULL)
						{

							memcpy(th->status.user, "XMPP", strlen("XMPP"));
							th->status.user[strlen(th->status.user)] = '\0';
						}
					}
					free(tcp_buf); tcp_buf = NULL;
				}

			}
		}else
		{
			memcpy(&tha.src, dst, sizeof(ip->ip_dst));
			memcpy(&tha.dst, src, sizeof(ip->ip_src));
			tha.port = dport << 16 | sport;
	
			for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
				th->nxt; th = th->nxt)
			{
				if (memcmp((char *)&tha, (char *)&th->addr,
						sizeof(th->addr)) == 0)
				{
					break;
				}
			}
			//No found previous packet
			if (th->nxt == NULL)
			{
				LOG_WARN("No previous packet, drop this packet");
				return;
			}

            //T5: server first send push flow, after server answer ACK
			if (th->seq == seq)
			{
				if (ts.tv_usec < th->status.t0.tv_usec )
				{
					th->status.t5.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
					th->status.t5.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
					
				}else{
					th->status.t5.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
					th->status.t5.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
					
				}
				LOG_INFO("T5: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);
			}

			//tcp_data
			int ip_len = ntohs(ip->ip_len);
			int ip_header_len = IP_HL(ip)*4;
			int tcp_header_len = TH_OFF(tcp)*4;
			int tcp_data_len = (ip_len - ip_header_len - tcp_header_len);
			if (tcp_data_len !=  0)
			{
				char *tcp_buf = (char *)malloc(tcp_data_len+1);
				memcpy(tcp_buf, (void *)tcp+tcp_header_len, tcp_data_len);
				tcp_buf[tcp_data_len]='\0';


				char* p = NULL;
				if (debug)
				{
					p = strstr(tcp_buf, "Content-Type");
				}else{
					p = strstr(tcp_buf, "DIGEST-MD5");
					
				}
				if (p != NULL)
				{
					if (ts.tv_usec < th->status.t0.tv_usec )
					{
						th->status.t6.tv_sec = ts.tv_sec - th->status.t0.tv_sec - 1;
						th->status.t6.tv_usec = 1000000 + ts.tv_usec - th->status.t0.tv_usec;
						
					}else{
						th->status.t6.tv_sec = ts.tv_sec - th->status.t0.tv_sec;
						th->status.t6.tv_usec = ts.tv_usec - th->status.t0.tv_usec;
						
					}
					th->status.succ_ack = ack;
					LOG_INFO("T6: %d.%d, seq: %u, ack: %u", ts.tv_sec, ts.tv_usec, seq, ack);

				}
				
				free(tcp_buf); tcp_buf = NULL;
			}
		}
	}    

	return;
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */

	//LOG_DEBUG("Packet number: %d", count);
	count++;
	
	/* define ethernet header */
	struct ether_header *_ethernet = (struct ether_header*)(packet);
	
	/* define/compute ip header offset */
	struct ip *_ip = (struct ip*)(packet + ETHER_HDRLEN);
	int size_ip = IP_HL(_ip)*4;
	if (size_ip < 20) {
		LOG_WARN("   * Invalid IP heade. length: %u bytes\n", size_ip);
		return;
	}

	/* determine protocol */	
	switch(_ip->ip_p) {
		case IPPROTO_TCP:
			LOG_DEBUG("Protocol: TCP");
			struct tcphdr *_tcp = (struct tcphdr*)(packet + ETHER_HDRLEN + size_ip);
			int size_tcp = TH_OFF(_tcp)*4;
			if (size_tcp < 20) {
				LOG_WARN("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			store_packet(args, header, _ip, _tcp);
			break;
		case IPPROTO_UDP:
			LOG_WARN("   Protocol: UDP");
			return;
		case IPPROTO_ICMP:
			LOG_WARN("   Protocol: ICMP");
			return;
		case IPPROTO_IP:
			LOG_WARN("   Protocol: IP");
			return;
		default:
			LOG_WARN("   Protocol: unknown");
			return;
	}
	
	return;
}

int tcp_sniff()
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	/* Init tcp status queue */
	TAILQ_INIT(&status_queue);

	/* Define the device */
	if(dev[0] == '\0')
	{
		LOG_WARN("input dev is null, tcp client try to lookup the devices");
		char* device = pcap_lookupdev(errbuf);
		if (device == NULL) {
			LOG_ERROR("tcp client couldn't find any default device: %s", errbuf);
			return(-1);
		}
		memcpy(dev, device, strlen(device));
		dev[strlen(device)] = '\0';
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		LOG_ERROR("couldn't get netmask for device %s: %s", dev, errbuf);
		net = 0;
		mask = 0;
	}
	LOG_DEBUG("dev: %s, net: %d, mask: %d\n", dev, net, mask);
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		LOG_ERROR("couldn't open device %s: %s", dev, errbuf);
		return(-1);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		LOG_ERROR("%s is not an Ethernet, only support Ethernet", dev);
		return(EXIT_FAILURE);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		LOG_ERROR("couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(-1);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		LOG_ERROR("couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(-1);
	}

	/* now we can set our callback function */
	pcap_loop(handle, packetnum, parse_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	LOG_NOTICE("Capture complete, num: packetnum:%d", packetnum);

	return 0;
}


















/* vim: set ts=4 sw=4 sts=4 tw=100 noet: */
