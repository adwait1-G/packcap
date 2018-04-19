#ifndef _ICMP_HANDLE_H_
#define _ICMP_HANDLE_H_


/*
 * File: icmp_handle.h
 *
 * Contents: This contains the macros and routines defined to parse the icmp header.
 */

#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<netinet/in.h>

#include"packcap.h"


void pkp_read_icmp_header(const unsigned char *packet);


#endif
