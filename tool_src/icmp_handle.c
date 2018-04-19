/* 
 * File: icmp_handle.c
 *
 * Contents: If the Protocol above the IPv4 Protocol is ICMP(Internet Control Message Protocol) , 
 * this file contains routines which are used to parse the ICMP header.
 *
 * ICMP protocol is used in the command "ping" to check if a machine is alive (Connected to the network) or not.
 *
 */


#include"pkp/icmp_handle.h"

void pkp_read_icmp_header(const unsigned char *packet) {

  pkp_icmp4_packet.header = (struct icmphdr *)(packet + 14 + 20);

  pkp_icmp4_packet.type = pkp_icmp4_packet.header->type;
  pkp_icmp4_packet.code = pkp_icmp4_packet.header->code;
  pkp_icmp4_packet.id = pkp_icmp4_packet.header->echo.id;
  pkp_icmp4_packet.seq = pkp_icmp4_packet.header->sequence;

  pkp_icmp4_packet.gw_raw_ipv4_addr.s_addr = pkp_icmp4_packet.header->gateway;
  sprintf(pkp_icmp4_packet.gw_ipv4_addr ,"%s" , inet_ntoa(pkp_icmp4_packet.gw_raw_ipv4_addr));

}
