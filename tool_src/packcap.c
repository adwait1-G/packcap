/*
 * File: packcap.c
 *
 * Contents:
 * 	1. Contains implementations of routines declared in pkp/packcap.h
 *
 * 	2.
 */
#include"pkp/packcap.h"
#include"pkp/ether_handle.h"

 /* TODO: If possible , put implementations of all the functions in another directory , create a dynamic shared object , and put only their declarations into a header files(Standard method).
 *
 */


void pkp_err_exit(char *errmsg) {
	fprintf(stderr , "%s\n" , errmsg);
	exit(1);
}

/*
 * This is used to print the timestamp and packet length in actual capture.
 */

void pkp_print_packet_details(const unsigned char *packet , struct pcap_pkthdr *packet_header) {

	static int count = 0;

	pkp_frame.raw_timestamp = packet_header->ts.tv_sec;
	struct tm *current_time = localtime(&pkp_frame.raw_timestamp);
	char tm_buffer[64];
	strftime(tm_buffer , sizeof(tm_buffer) , "%Y-%m-%d %H:%M:%S" , current_time);


	snprintf(pkp_frame.current_time, sizeof(pkp_frame.current_time) , "%s.%ld" , tm_buffer , pkp_frame.raw_timestamp);
	pkp_frame.length = packet_header->len;

	/*
	 * packet_header->len = packet_header->caplen in our tool.
	 * Reason: The capture buffer size = 65535. The theoritically largest size of a frame.
	 */


	fprintf(fs_csv , "%s , %d , %s , %s , %s , %s , %s , %s , %u , %u \n" , pkp_frame.current_time , pkp_frame.length , pkp_frame.src_eth_addr , pkp_frame.dest_eth_addr , pkp_frame.l3_protocol , pkp_ipv4_packet.src_ipv4_addr , pkp_ipv4_packet.dest_ipv4_addr , pkp_ipv4_packet.l4_protocol , pkp_tcp_segment.src_port , pkp_tcp_segment.dest_port);
	fprintf(stdout , "%s , %d , %s , %s , %s , %s , %s , %s , %u , %u \n" , pkp_frame.current_time , pkp_frame.length , pkp_frame.src_eth_addr , pkp_frame.dest_eth_addr , pkp_frame.l3_protocol , pkp_ipv4_packet.src_ipv4_addr , pkp_ipv4_packet.dest_ipv4_addr , pkp_ipv4_packet.l4_protocol , pkp_tcp_segment.src_port , pkp_tcp_segment.dest_port);
	if(!strcmp(pkp_ipv4_packet.l4_protocol, "ICMP")) {
		printf("ICMP packets detected\n" );
	}
}



void pkp_packet_handler(unsigned char *arg , struct pcap_pkthdr *packet_header , const unsigned char *packet) {
	pkp_read_eth_header(packet);
	pkp_read_ipv4_header(packet);
	pkp_read_tcp_header(packet);


	fs_csv = fopen(pkp_csv_file , "a+");
	pkp_print_packet_details(packet , packet_header);
	fclose(fs_csv);



}


void pkp_dumpinto_file() {

	memset(pkp_dump_file , '\0' , sizeof(pkp_dump_file));
	printf("\nEnter the dumpfile name:(Maximum of 40 characters) ");
	scanf("%s" , pkp_dump_file);

	pkp_sniff.dumpfile = pcap_dump_open(pkp_sniff.handle , pkp_dump_file);
	if(pkp_sniff.dumpfile == NULL)
		pkp_err_exit("Error in creating the pcap_dumper_t structure.");

	if(pcap_loop(pkp_sniff.handle ,DEFAULT_PACKET_COUNT_LIMIT , &pcap_dump  , (char *)pkp_sniff.dumpfile) < 0)
		pkp_err_exit("Error in capturing packets. routine: pcap_loop()");
}


void pkp_live_relay() {
	memset(pkp_csv_file , '\0' , sizeof(pkp_csv_file));
	printf("Enter the csv file name:(Maximum of 40 characters) ");
	scanf("%s" , pkp_csv_file);

	pcap_loop(pkp_sniff.handle , DEFAULT_PACKET_COUNT_LIMIT , pkp_packet_handler , NULL);
}

void pkp_print_list_filters() {
	printf("\nThese are the network device details about your machine: \n");
	system("ifconfig");

	printf("\nThe Network Device being used: %s\n" , pkp_device.name);

	printf("\nCapture traffic with\t");
	printf("\n0. No filters(Capture all network traffic)");
	printf("\n1. Either source or destination IPv4 Addresses ");
	printf("\n2. Specific Source IPv4 Address ");
	printf("\n3. Specific Destination IPv4 Address ");
	printf("\n4. Either source or destination IPv6 Addresses ");
	printf("\n5. Specific Source IPv6 Address ");
	printf("\n6. Specific Source IPv6 Address ");
	printf("\n7. Either Source or Destination port number");
	printf("\n8. specific Source port number");
	printf("\n9. specific Destination port number");
	printf("\n\nRefer /etc/services to choose the port number and know the corresponding type of traffic which will be captured.\n\n");
	printf("\n10. Traffic related to a particular website(Eg: www.google.com)");
	printf("\n11. Specific Layer 3 protocol");
	printf("\n12. Specific Layer 4 protocol(Under IPv4)");
	printf("\n13. IPv4 Broadcast packets.");
	printf("\n14. Ethernet Broadcast packets.");
	printf("\n15. Gateway capture(Applicable only if the machine is a gateway to a network)");

}

void pkp_choose_filter(int fc) {
	char temp_addr[30];
	int port;
	memset(temp_addr , '\0' , sizeof(temp_addr));
	memset(pkp_sniff.filter_exp , '\0' , sizeof(pkp_sniff.filter_exp));
	if(fc == 0) {
			printf("Capturing All packets.\n\n");
	}
	else if(fc == 1) {
		printf("\nEnter the IPv4 Address: ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "host %s" , temp_addr);
		printf("\nCapturing all packets with either source or destination IPv4 address = %s\n" , temp_addr);
	}
	else if(fc == 2) {
		printf("Enter the IPv4 Address: ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "src host %s" , temp_addr);
		printf("\nCapturing all packets with source IPv4 address = %s\n" , temp_addr);
	}
	else if(fc == 3) {
		printf("Enter the IPv4 Address: ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "dst host %s" , temp_addr);
		printf("\nCapturing all packets with destination IPv4 addres = %s\n" , temp_addr);
	}
	else if(fc == 4 || fc == 5 || fc == 6) {
		printf("Not supported.");
	}
	else if(fc == 7) {
		printf("Enter the port number: ");
		scanf("%d" , &port);
		printf("Port = %d\n" , port);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "port %d" , port);
		printf("\nCapturing all packets with either source or destination port number = %d\n" , port);
	}
	else if(fc == 8) {
		printf("Enter the port number: ");
		scanf("%d" , &port);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "src port %d" , port);
		printf("\nCapturing all packets with source port number = %d\n" , port);
	}
	else if(fc == 9) {
		printf("Enter the port number: ");
		scanf("%d" , &port);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "dest port %d" , port);
		printf("\nCapturing all packets with either destination port number = %d\n" , port);
	}
	else if(fc == 10) {
		printf("Enter the website: ");
		scanf("%s" , temp_addr);
		printf("\nNote: This option might take a while because the IP Address has to be found out using DNS Lookup.\n\n");

		struct hostent *host = gethostbyname(temp_addr);
		if(host == NULL)
			pkp_err_exit("Error in Reverse DNS Lookup.Routine: gethostbyname()");

		int i = 0;
		while(host->h_addr_list[i] != NULL) {
			snprintf(temp_addr , sizeof(temp_addr) , "%s" , inet_ntoa(*(struct in_addr*)(host->h_addr_list[i])));
			printf("%d. %s\n" , i , temp_addr);
			i++;
		}
		printf("NOTE: TODO: A URL lead to several servers which is denoted by the multiple IP Addresses returned by the DNS lookup.So , A mechanism should be built which detects the IP Address.\nTill then , Guess the IP Address.\n");
		printf("Choose the IP Address(Enter the serial no.): ");
		scanf("%d" , &i);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "host %s" , inet_ntoa(*(struct in_addr*)(host->h_addr_list[i])));

	}
	else if(fc == 11) {
		printf("\nChoices: ip , arp : ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "ether proto %s" , temp_addr);
	}
	else if(fc == 12) {
		printf("\nChoices: tcp , udp , icmp: ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "ip proto %s" , temp_addr);
	}
	else if(fc == 13) {
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "ip broadcast");
	}
	else if(fc == 14) {
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "ether broadcast");
	}
	else if(fc == 15) {
		printf("Enter the IP Address: ");
		scanf("%s" , temp_addr);
		snprintf(pkp_sniff.filter_exp , sizeof(pkp_sniff.filter_exp) , "gateway %s" , temp_addr);
	}
	else
		pkp_err_exit("\n\nInvalid choice entered. Terminating...");

	printf("Filter: %s\n" , pkp_sniff.filter_exp);


}



void pkp_apply_filter() {
	if(pcap_compile(pkp_sniff.handle , &pkp_sniff.filter ,  pkp_sniff.filter_exp , 0 , pkp_device.raw_ip_addr) == -1)
		pkp_err_exit("\nError in compiling the filter expression.Routine: pcap_compile(). Terminating...\n\n");

	if(pcap_setfilter(pkp_sniff.handle , &pkp_sniff.filter) == -1)
		pkp_err_exit("Error in setting filter.Routine: pcap_setfilter()");
}


void pkp_signal_handler(int signal_number) {

	printf("Interrupted by signal %d\n\n" , signal_number);
	if(pcap_stats(pkp_sniff.handle , &pkp_sniff.stat) == -1)
		pkp_err_exit("Error in collecting the statistics of the sniff session.");

	printf("Total packets received: 		%d\n" , pkp_sniff.stat.ps_recv);
	printf("Packets dropped by Kernel: 	%d\n" , pkp_sniff.stat.ps_drop);
	printf("Packets dropped by Network Card / Driver: %d\n" , pkp_sniff.stat.ps_ifdrop);

	printf("Percentage packets dropped : %f\n" , ((float)((pkp_sniff.stat.ps_drop) + (pkp_sniff.stat.ps_ifdrop))) / pkp_sniff.stat.ps_recv);
}
