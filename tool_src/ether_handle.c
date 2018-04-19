/*
 * File: ether_handle.c
 *
 * Contents:
 *
 * 1. Basic Ethernet header parsing and decoding routines.
 * 2. Support present for most generally used protocols.
 * At present ,
 * 	a. IPv4
 * 	b. IPv6
 * 	c. ARP
 * 	d. ReARP
 * 	e. VLAN		Not sure about this.
 * 	f. LOOPBACK
 */

#include"pkp/packcap.h"


void pkp_read_eth_header(const unsigned char *packet) {

	pkp_frame.pkp_eth_header = (struct ether_header *)(packet);


 /*
 * XXX: Never ever use this strcpy routine to copy stuff.
 * This is causing stack smashes and a lot of chaos.
 * Definitely , if it was used , the tool would be a source of stack overflow vulnerabilities.
 * As this tool is run as root user , The attacker gets the root shell. SHIT!
 *
 * In fact , the stack got smashed. So , definitely security critical part.
 *
 * Remedy: Using sprintf() to copy buffer data.
 * TODO:Refering to Issue #1.
 * 	The ethernet addresses are not getting copied properly.
 * 	Should resolve it before submission.
 */


 sprintf(pkp_frame.src_eth_addr , "%s" , ether_ntoa(pkp_frame.pkp_eth_header->ether_shost));
 sprintf(pkp_frame.dest_eth_addr , "%s" , ether_ntoa(pkp_frame.pkp_eth_header->ether_dhost));

	switch((unsigned short int)(pkp_frame.pkp_eth_header->ether_type)) {
		case 0x0008:
			pkp_frame.l3_protocol = "IPv4";
			pkp_read_ipv4_header(packet);
			break;
		case 0xdd86:
			pkp_frame.l3_protocol = "IPv6";
			break;
		case 0x0608:
			pkp_frame.l3_protocol = "ARP";
			break;
		case 0x3580:
			pkp_frame.l3_protocol = "ReARP";
			break;
		case 0x0090:
			pkp_frame.l3_protocol = "LoopBack";
			break;
		default:
			pkp_frame.l3_protocol = "Unkwown/Not Supported";

		}

/*
 * XXX: Respect endianess of the architecture while writing the switch cases. This is what happened.
 * case 0x0800: ...		. This was written because in net/ethernet.h , #define ETHERTYPE_IP 0x800. 	But this is in network order.
 * Should write it in little_endian order.
 *
 * Got this while looking through hexdump of the pcap file.
 *
 */

}
