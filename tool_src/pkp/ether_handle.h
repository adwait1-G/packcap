#ifndef _ETHER_HANDLE_H_
#define _ETHER_HANDLE_H_

#include<pcap.h>
#include<net/ethernet.h>
#include<netinet/ether.h>


void pkp_read_eth_header(const unsigned char *packet);

#endif
