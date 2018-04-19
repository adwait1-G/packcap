/*
 * File: main.c
 *
 * Contents:
 * 	1. This is the main sourcefile around which everything is built.
 * 	2. Basic device detection , opening a sniffing session and calling the sniff handler happens in this Sourcefile.
 */


#include"pkp/packcap.h"
#include"pkp/ether_handle.h"


int main() {


/*
 * Finding default device .
 * Routine: pcap_lookupdev()
 */
	pkp_device.name = pcap_lookupdev(pkp_device.error_buffer);
	if(pkp_device.name == NULL)
		pkp_err_exit("Error in finding default device. \nRoutine: pcap_loopupdev()");


/*
 * Getting details of the device found .
 * Routine: pcap_lookupnet()
 */


	if(pcap_lookupnet(pkp_device.name , &pkp_device.raw_ip_addr , &pkp_device.raw_subnet_mask , pkp_device.error_buffer) == -1)
		pkp_err_exit("Error in finding details about the device. \nRoutine: pcap_lookupnet()");

/*
 * Converting Network forms of IP Address and Subnet Mask into human-readable strings.
 * Routine: inet routines.
 */

	pkp_device.ip_address.s_addr = pkp_device.raw_ip_addr;
	strcpy(pkp_device.str_ip_addr , inet_ntoa(pkp_device.ip_address));
	if(pkp_device.str_ip_addr == NULL)
		pkp_err_exit("Error: Unable to convert raw IP address into human readable form. Routine: inet_ntoa()");


	pkp_device.ip_address.s_addr = pkp_device.raw_subnet_mask;
	strcpy(pkp_device.str_subnet_mask , inet_ntoa(pkp_device.ip_address));
	if(pkp_device.str_subnet_mask == NULL)
		pkp_err_exit("Error: Unable to covert raw Subnet mask into human readable form. Routine: inet_ntoa()");

	printf("Device = %s\n" 	     , 	pkp_device.name);
	printf("Ip Address = %s\n"   , 	pkp_device.str_ip_addr);
	printf("Subnet mask = %s\n\n"  , 	pkp_device.str_subnet_mask);




/*
 * Opening a live sniffing session. Get a handle to manage the session.
 * Routine: pcap_open_live()
 */

	pkp_sniff.handle = pcap_open_live(pkp_device.name , BUFSIZ , pkp_sniff.packet_count_limit , pkp_sniff.timeout_limit , pkp_device.error_buffer);
	if(pkp_sniff.handle == NULL)
		pkp_err_exit("Error:  Unable to open a live sniffing session in the device specified. Routine: pcap_open_live()");


/*
 * Checking if the default device uses/supports Ethernet headers. Or Checking if the Data-Link Protocol is the Ethernet Protocol.
 * Routine: pcap_datalink()
 */

	if(pcap_datalink(pkp_sniff.handle) != DLT_EN10MB)
		pkp_err_exit("Error: Device does not support Ethernet Headers.");

		/*
		 * In the next part , Ask for what type of traffic to be captured.
		 */

			int filter_choice_0;
			int filter_choice_1;

		 	printf("\nChoose the type of traffic filter: \n");
		 	pkp_print_list_filters();
			printf("\n\nEnter option: ");
		 	scanf("%d" , &filter_choice_0);

			pkp_choose_filter(filter_choice_0);
			pkp_apply_filter();


	/*
	 * Should Give options to the user.
	 * 1. Should the packets be dumped be into a file . That pcap file can be opened later using a tool like wireshark.
	 * 2. Give the live relay on the screen. Sub options should be given.
	 				a. Complete dump(From which a person cannot make out much)
					b. Dump packets of a particular protocol.
					c. Dump packets of a particular protocol.
					d. Dump packets which are data between host machine and a particular website(eg: youtube.com)
			If time permits , Add more features and make it more user controllable.
	*/

	printf("\n\nOptions: \nDump packets into a .pcap file -- 0 \nDump packets onto the live relay window -- 1\n");
	unsigned short int choice;
	if(scanf("%d" , &choice) != 1)
		pkp_err_exit("\nError in inputting the choices. Choices: \n(0)Dump into a file \n(1)Dump onto the live relay window");

	if(choice == 0) {
		printf("\nChosen to dump the packets into a dumpfile.");
		pkp_dumpinto_file();
	}
	else if(choice == 1) {
		printf("\nThe live relay option is chosen!\n");
		pkp_live_relay();
	}
	else
		pkp_err_exit("Wrong option. Options: 0(Dump into a file) or 1(Dump onto the live relay window");

		signal(SIGINT, pkp_signal_handler());
	return 0;
}
