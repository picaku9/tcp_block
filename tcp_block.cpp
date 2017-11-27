#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#pragma pack(1)

#define HTTP_REQUEST_FUNCTION 	6

const char method[HTTP_REQUEST_FUNCTION][8] = {"GET","HOST","HEAD","PUT","DELETE","OPTIONS"};

struct rst_packet {
	struct libnet_ethernet_hdr eth_header;
	//dst mac
	//src mac
	//eth_header->ether_type = ETHERTYPE_IP;
	struct libnet_tcp_hdr tcp_header;
	//ip4_header->ip_v = htons(4);
	//ip4_header->ip_hl = htons(5);
	//ip4_header->ip_len = htons(40);
	//ip4_header->ip_p = IPPROTO_TCP;
	//ip4_header->ip_off = htons(IP_DF);
	//ip4_header->ip_ttl = 48;
	//ip4_header->ip_src;
	//ip4_header->ip_dst;
	struct libnet_ipv4_hdr ip4_header;
	//tcp_header->th_sport; 받은 패킷의 dest port
	//tcp_header->th_dport; 받은 패킷의 source port
	//tcp_header->th_seq; 받은 패킷의 ack
	//tcp_header->th_ack; 받은 seq+ tcp_len (total_len - 40)
	//tcp_header->th_off = htons(5);
	//tcp_header->th_flags = htons(TH_RST); or htons(TH_FIN)
	//tcp_header->th_win = 0;
	//tcp_header->th_sum = 0;
};
void make_rst(struct rst_packet *rst) {
	rst->eth_header.ether_type = htons(ETHERTYPE_IP);

	rst->ip4_header.ip_v = htons(4);
	rst->ip4_header.ip_hl = htons(5);
	rst->ip4_header.ip_len = 40;
	rst->ip4_header.ip_p = IPPROTO_TCP;
	rst->ip4_header.ip_off = IP_DF;
	rst->ip4_header.ip_ttl = 48;

	rst->tcp_header.th_off = 5;
	rst->tcp_header.th_flags = TH_RST;
	rst->tcp_header.th_win = 0;
	rst->tcp_header.th_sum = 0;
}

void print_ether(uint8_t *ether) {
	printf("MAC address : ");
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ether[i]);
	}
	printf("%02x\n", ether[5]);
}

void usage() {
	printf("syntax: tcp_block <interface>\n");
	printf("sample: tcp_block en0\n");
}

int main(int argc, char *argv[]) {
	int flag = 0;
	if(argc != 2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	struct rst_packet rst_p;

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		printf("\neth header size : %d\n", sizeof(struct libnet_ethernet_hdr));
		printf("\nip header size : %d\n", sizeof(struct libnet_ipv4_hdr));
		printf("\ntcp header size : %d\n", sizeof(struct libnet_tcp_hdr));

		printf("\n_______________pcap_next_ex ____________ \n");
		printf("\nprint REAL packet by HEX: \n");

		for(int j = 0; j < (header->len)/16 ; j++) {
			for(int i = 0; i < 8; i++) {
				printf("%02x ", ((uint8_t *)packet)[i+j*16]);
			}
			printf("  ");
			for(int i = 8; i < 16; i++) {
				printf("%02x ", ((uint8_t *)packet)[i+j*16]);
			}
			printf(" \n");
		}

		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr *)packet;
		eth->ether_type = ntohs(eth->ether_type);
//		printf("이더넷 타입: 0x%04X\n", eth->ether_type);
		if(eth->ether_type == ETHERTYPE_IP){
			printf("\nIt's IP\n");
			struct libnet_ipv4_hdr* ip4 = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H );
//			printf("ip 타입: %d\n", ip4->ip_p);

			char ip_src[INET_ADDRSTRLEN];
			char ip_dst[INET_ADDRSTRLEN];

    		printf("ip_src : %s\n",inet_ntop(AF_INET, &ip4->ip_src, ip_src, INET_ADDRSTRLEN));
   			printf("ip_des : %s\n",inet_ntop(AF_INET, &ip4->ip_dst, ip_dst, INET_ADDRSTRLEN));

			if(ip4->ip_p == IPPROTO_TCP){
				printf("\nIt's TCP\n");

				//first check packet is http.request.
				struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
				uint16_t tcp_len = ntohs(ip4->ip_len) - LIBNET_IPV4_H;
				uint16_t tcp_payload_len = tcp_len - tcp->th_off*4;
				uint8_t *tcp_payload = (uint8_t *)packet + LIBNET_IPV4_H + tcp->th_off*4;
				if(tcp_payload_len ==  0) {
					printf("There is no tcp data\n");
					flag = 0;
				}
				else {
					for(int i = 0; i<HTTP_REQUEST_FUNCTION;i++){
						if(memcmp(tcp_payload, method[i], strlen(method[i]))) {
							printf("\nIt's HTTP.request\n");
							printf("tcp_payload_len : %d\n", tcp_payload_len);
							flag = 1;
							break;
						}
						else{
							flag = 0;
						}
					}
				}

				if(flag == 0) {
					//Forward RST
					memcpy(rst_p.eth_header.ether_shost, eth->ether_shost, 6);
					memcpy(rst_p.eth_header.ether_dhost, eth->ether_dhost, 6);

					memcpy(&(rst_p.ip4_header.ip_src), &(ip4->ip_src), 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_seq, 4);
					memcpy(&rst_p.tcp_header.th_ack, &tcp->th_ack, 4);
					make_rst(&rst_p);

					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));

					//Backward RST
					
					memcpy(&rst_p.eth_header.ether_shost, &eth->ether_dhost, 6);
					memcpy(&rst_p.eth_header.ether_dhost, &eth->ether_shost, 6);

					memcpy(&rst_p.ip4_header.ip_src, &ip4->ip_dst, 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_src, 4);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_ack, 4);
//					memcpy(rst_p.ip4_header.th_ack, (tcp->th_seq + tcp_payload_len), 4);
					memset(&rst_p.tcp_header.th_ack, 0, 4);

					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));
					
				}
				if(flag == 1) {
				//Forward RST
					memcpy(rst_p.eth_header.ether_shost, eth->ether_shost, 6);
					memcpy(rst_p.eth_header.ether_dhost, eth->ether_dhost, 6);

					memcpy(&(rst_p.ip4_header.ip_src), &(ip4->ip_src), 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_seq, 4);
					memcpy(&rst_p.tcp_header.th_ack, &tcp->th_ack, 4);
					make_rst(&rst_p);

					printf("---------------RST packet--------------------\n");
					print_ether(rst_p.eth_header.ether_dhost);
					print_ether(rst_p.eth_header.ether_shost);
					printf("ether type : 0x%04x\n", rst_p.eth_header.ether_type);
					printf("ip_src : %s\n",inet_ntop(AF_INET, &rst_p.ip4_header.ip_src, ip_src, INET_ADDRSTRLEN));
					printf("ip_des : %s\n",inet_ntop(AF_INET, &rst_p.ip4_header.ip_dst, ip_dst, INET_ADDRSTRLEN));
					printf("ip_version(4) : %x\n", rst_p.ip4_header.ip_v);
					printf("ip_hl(5) : %x\n", rst_p.ip4_header.ip_hl);
					printf("ip_len(40) : %04x\n", rst_p.ip4_header.ip_len);

					printf("ack num: 0x%08x\n",ntohl(rst_p.tcp_header.th_ack));
					printf("seq num: 0x%08x\n",ntohl(rst_p.tcp_header.th_seq));


					printf("\nprint RST packet by HEX: \n");
					printf("size of rst_packet: %d\n", sizeof(struct rst_packet));
					for(int j = 0; j < sizeof(struct rst_packet)/16 ; j++) {
						for(int i = 0; i < 8; i++) {
							printf("%02x ", ((uint8_t *)&rst_p)[i+j*16]);
						}
						printf("  ");
						for(int i = 8; i < 16; i++) {
							printf("%02x ", ((uint8_t *)&rst_p)[i+j*16]);
						}
						printf(" \n");
					}


					for(int i = (sizeof(struct rst_packet)/16)*16; i < (sizeof(struct rst_packet)/16)*16+ sizeof(struct rst_packet)%16; i++) {
						printf("%02x ", ((uint8_t *)&rst_p)[i]);
					}

					printf("\n\n");

					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));

				//Backward FIN redirect.

				}
			}



		}
	}

	return 0;
}
