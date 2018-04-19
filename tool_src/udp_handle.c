/*
 * File: udp_handle.c
 *
 * Contents:
 * 	1. If the Transport layer protocol is UDP(User Datagram Protocol) , this sourcefile will contain routines which are used to parse the UDP header.
 */

 #include"pkp/packcap.h"
 #include"pkp/udp_handle.h"

 void pkp_read_udp_header(const unsigned char *packet) {

   pkp_udp_dgram.header  = (struct udphdr *)(packet + 14 + 20);
   pkp_udp_dgram.src_port = ntohs(pkp_udp_dgram.header->source);
   pkp_udp_dgram.dest_port = ntohs(pkp_udp_dgram.header->dest);
   pkp_udp_dgram.length = ntohs(pkp_udp_dgram.header->len);

 }
