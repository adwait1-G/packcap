#ifndef _IPVX_HANDLE_H_
#define _IPVX_HANDLE_H_

#include<netinet/ip.h>
#include<netinet/ip6.h>
#include<net/ethernet.h>
#include<arpa/inet.h>
#include<pcap.h>


//#define ETHER_HEADER_SIZE sizeof(struct ether_header) Not working.

void pkp_read_ipv4_header(const unsigned char *packet);






#endif
