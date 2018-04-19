/*
 * File: ipvx_handle.c
 *
 * Contents:
 * 	1. IP (Both v4 and v6) parsing routines.
 *	2. Identifying the Layer 4 protocol. These are the protocols supported:
 *		1. TCP - Both IPv4 and IPv6.
 *		2. UDP - Both IPv4 and IPv6
 *		3. ICMP - Only IPv4
 *		4. IGMP - Only Ipv4
 *
 *	3. There are many protocols for which we want to extend support.
 *		1. ICMP for IPv6
 *		2. SCTP
 *		3. SMP
 *		4. Routing protocol packets like EIGRP , OSPF , RP .
 */


#include"pkp/packcap.h"


void pkp_read_ipv4_header(const unsigned char *packet) {

	pkp_ipv4_packet.header = (struct iphdr *)(packet + 14);

/*
 * That +14  , 14 is the sizeof(struct ether_header).
 * TODO: Change the +14 to sizeof() or something. The value should not be hardcoded.
 */

	switch (pkp_ipv4_packet.header->protocol) {

		case 1 :
			pkp_ipv4_packet.l4_protocol = "ICMP";
			break;
		case 2 :
			pkp_ipv4_packet.l4_protocol = "IGMP";
			break;
		case 6 :
			pkp_ipv4_packet.l4_protocol = "TCP";
			break;
		case 17 :
			pkp_ipv4_packet.l4_protocol = "UDP";
			break;
		default:
			pkp_ipv4_packet.l4_protocol = "Unknown/Not Supported";
	}

	char *temp_ip_addr;
	struct in_addr temp_addr;
	temp_addr.s_addr = pkp_ipv4_packet.header->saddr;
	sprintf(pkp_ipv4_packet.src_ipv4_addr , "%s" , inet_ntoa(temp_addr));

	temp_addr.s_addr = pkp_ipv4_packet.header->daddr;
	sprintf(pkp_ipv4_packet.dest_ipv4_addr , "%s" , inet_ntoa(temp_addr));
}
