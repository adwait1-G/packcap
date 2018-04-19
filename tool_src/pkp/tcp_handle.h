#ifndef _TCP_HANDLE_H_
#define _TCP_HANDLE_H_


#include<netinet/tcp.h>
#include<arpa/inet.h>
#include"packcap.h"


void pkp_read_tcp_header(const unsigned char *packet);


#endif
