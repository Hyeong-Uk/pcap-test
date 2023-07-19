#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

unsigned int broadcast = 0; //0: not broadcast. 1: broadcast.

void print_mac(u_int8_t *m, unsigned int type) {
	if (type == 1) {
		printf("Source MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", m[0], m[1], m[2], m[3], m[4], m[5]);
	}
	else if (type == 2) {
		printf("Destination MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", m[0], m[1], m[2], m[3], m[4], m[5]);
	}
	else {
		fprintf(stderr, "wrong type. type 1: source address, type 2: destination address\n");
		exit(0);
	}
	
	if ((short)m[0] == 0xFF && (short)m[1] == 0xFF && (short)m[2] == 0xFF && (short)m[3] == 0xFF && (short)m[4] == 0xFF && (short)m[5] == 0xFF) {
		printf("		Broadcast!!!\n");
		broadcast = 1;
	}
	
	return;
}

void print_ipaddr(struct in_addr ip, unsigned int type) {
	u_int32_t haddr = ntohl(ip.s_addr);
	
	if (type == 1) {
		printf("Source IP Address: %d.%d.%d.%d\n", (u_int8_t)(haddr >> 24), (u_int8_t)(haddr >> 16), (u_int8_t)(haddr >> 8), (u_int8_t)haddr);
	}
	else if (type == 2) {
		printf("Destination IP Address: %d.%d.%d.%d\n", (u_int8_t)(haddr >> 24), (u_int8_t)(haddr >> 16), (u_int8_t)(haddr >> 8), (u_int8_t)haddr);
	}
	else {
		fprintf(stderr, "wrong type. type 1: source address, type 2: destination address\n");
		exit(0);
	}
	
	return;
}

void print_port(u_int16_t port, unsigned int type) {
	u_int16_t hport = ntohs(port);

	if (type == 1) {
		printf("Source Port Number: %d\n", hport);
	}
	else if (type == 2) {
		printf("Destination Port Number: %d\n", hport);
	}
	else {
		fprintf(stderr, "wrong type. type 1: source port number, type 2: destination port number\n");
		exit(0);
	}
	
	return;
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		print_mac(eth_hdr->ether_shost, 1);
		print_mac(eth_hdr->ether_dhost, 2);
		//printf("%02X, %02X\n", *(packet), *(packet + 1)); //test
		
		if (broadcast == 1) {
			printf("Sender IP Address: %d.%d.%d.%d\n", (u_int8_t)(*(packet + 28)), (u_int8_t)(*(packet + 29)), (u_int8_t)(*(packet + 30)), (u_int8_t)(*(packet + 31)));
			printf("Target IP Address: %d.%d.%d.%d\n", (u_int8_t)(*(packet + 38)), (u_int8_t)(*(packet + 39)), (u_int8_t)(*(packet + 40)), (u_int8_t)(*(packet + 41)));
			broadcast = 0;
			continue;
		}
		
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + 14);
		print_ipaddr(ip_hdr->ip_src, 1);
		print_ipaddr(ip_hdr->ip_dst, 2);
		
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + 34);
		print_port(tcp_hdr->th_sport, 1);
		print_port(tcp_hdr->th_dport, 2);
	}

	pcap_close(pcap);
}
