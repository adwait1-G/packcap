/*
 * File: tcp_handle.c
 *
 * Contents: This source file contains routines routines to parse the TCP(Transmission Control Protocol) header.
 * TCP Protocol is a Layer 4 protocol.
 *
 * The parser routine parses and make note of important things like
 * 	1. Source port
 * 	2. Destination port
 * 	3. Swquence Number
 * 	4. Acknoledgement number
 * 	5. What kind of packet it is.
 * 		a. ACK
 * 		b. SYN
 * 		c. FIN
 * 		d. RST
 * 		e. PUSH
 * 		f. URG
 *
 *
 */

#include"pkp/tcp_handle.h"
#include"pkp/packcap.h"

void pkp_read_tcp_header(const unsigned char *packet) {

  pkp_tcp_segment.header = (struct tcphdr *)(packet + 14 + 20);

  pkp_tcp_segment.src_port = ntohs(pkp_tcp_segment.header->th_sport);
  pkp_tcp_segment.dest_port = ntohs(pkp_tcp_segment.header->th_dport);
  pkp_tcp_segment.seq_no = ntohl(pkp_tcp_segment.header->th_seq);
  pkp_tcp_segment.ack_no = ntohl(pkp_tcp_segment.header->th_ack);
  pkp_tcp_segment.flags = pkp_tcp_segment.header->th_flags;

  pkp_tcp_segment.fin = (pkp_tcp_segment.flags) & 0x80;
  pkp_tcp_segment.syn = (pkp_tcp_segment.flags) & 0x60;
  pkp_tcp_segment.rst = (pkp_tcp_segment.flags) & 0x20;
  pkp_tcp_segment.push = (pkp_tcp_segment.flags) & 0x10;
  pkp_tcp_segment.ack = (pkp_tcp_segment.flags) & 0x08;
  pkp_tcp_segment.urg = (pkp_tcp_segment.flags) & 0x04;




 }
