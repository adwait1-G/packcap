#ifndef __PACKCAP_H__
#define __PACKCAP_H__

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<signal.h>
#include<time.h>
#include<pcap.h>


#include"ether_handle.h"
#include"ipvx_handle.h"

/*
 * A few constants used.
 */

#define DEFAULT_PACKET_COUNT_LIMIT -1



/*
 * TODO:
 * 1. Put implementations of all the routines in another directory.
 * 2. Create a dynamic shared object of the routines (so that the main executable is light).
 * 3. Put all the routine declarations into a header file (Standard method).
 *
 */


/*
 * pkp_device_details: This structure contains all the details of the default device .
 */

 char pkp_csv_file[50];
 char pkp_dump_file[50];


struct pkp_device_details {
	char 		*name;
	char 		error_buffer[PCAP_ERRBUF_SIZE];
	char 		str_ip_addr[13];
	char 		str_subnet_mask[13];
	struct in_addr 	ip_address;
	bpf_u_int32 	raw_ip_addr;
	bpf_u_int32 	raw_subnet_mask;


} pkp_device;


/*
 * pkp_sniff_session: This structure contains all the details about the current sniffing session.
 */


struct pkp_sniff_session {
	int 		packet_count_limit;
	int 		timeout_limit;
	pcap_t 		*handle;
  pcap_dumper_t *dumpfile;
  struct bpf_program filter;
  char filter_exp[50] ;
  struct pcap_stat stat;
} pkp_sniff;



/*
 * pkp_frame_details: This structure contains all the details of the packet under analysis.
 */

struct pkp_frame_details {

	struct pcap_pkthdr 	*pkp_pkt_header;
	long int 		raw_timestamp;
	char 			current_time[64];
	unsigned short int 	length;

	struct ether_header 	*pkp_eth_header;
	char src_eth_addr[20];
	char dest_eth_addr[20];
	char *l3_protocol;

} pkp_frame;


/*
 * ipv4_packet: If the frame's layer3 protocol is IPv4 , then this structure will contain all the details regarding ipv4 header.
 */

struct ipv4_packet {

	struct iphdr *header;
	char src_ipv4_addr[20];
	char dest_ipv4_addr[20];
	char *l4_protocol;
} pkp_ipv4_packet;


/*
 * arp_packet: If the frame's layer 3 protocol is ARP , thne this structure will contain/lead to all the details regarding the ARP header.
 */


 struct arp_packet {

	 struct arphdr *header;


 } pkp_arp_packet;




struct tcp_segment {
	struct tcphdr *header;
	unsigned short int src_port;
	unsigned short int dest_port;
	unsigned int seq_no;
	unsigned int ack_no;
	unsigned char flags;
	unsigned char fin , syn , rst , push , ack , urg;
} pkp_tcp_segment;


struct udp_datagram {
	struct udphdr *header;
	unsigned short int src_port ;
	unsigned short int dest_port;
	unsigned short int length;
};

struct udp_datagram pkp_udp_dgram;

struct icmp4_packet {
		 struct icmphdr *header;
		 char type;
		 char code;
		 unsigned short int id;
		 unsigned short int seq;
		 struct in_addr gw_raw_ipv4_addr;
		 char gw_ipv4_addr[20];
	 };
	 struct icmp4_packet pkp_icmp4_packet;




	 FILE *fs_csv;



/*
 * Error Message printing routine of packcap.
 */

void pkp_err_exit(char *errmsg) ;

/*
 * This Routine prints the packet length.
 */

void pkp_print_packet_len(const unsigned char *packet , struct pcap_pkthdr *packet_header);

/*
 * This is the packcap packet handler.
 * XXX: Thoughts:
 * 	1. Planning to have different handlers for different types of packets.
 * 	2. Have one universal handler and then distribute work among other relevant routines.
 */

void pkp_packet_handler(unsigned char *arg , struct pcap_pkthdr *packet_header , const unsigned char *packet) ;


//void pkp_pcap_dump_handler(unsigned char *dumpfile , const struct pcap_pkthdr *header , const unsigned char *pkt_data);



 /*
  * This routine will dump all the packets mercilessly into a file.
  */
void pkp_dumpinto_file();

void pkp_dumpfile_handler(unsigned char *arg , struct pcap_pkthdr *packet_header , const unsigned char *packet);


  /*
   * This routine will dump the details into the live relay window.
   */

void pkp_live_relay();

void pkp_choose_filter(int fc);
void pkp_apply_filter();
void pkp_print_list_filters();



#endif
