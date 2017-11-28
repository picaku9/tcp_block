#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#pragma pack(2)

#define HTTP_REQUEST_FUNCTION 	6

//const char method[HTTP_REQUEST_FUNCTION][8] = {"GET","HOST","HEAD","PUT","DELETE","OPTIONS"};
char *get_str = "GET";

struct rst_packet {
	struct libnet_ethernet_hdr eth_header;
	//dst mac
	//src mac
	//eth_header->ether_type = ETHERTYPE_IP;
	struct libnet_ipv4_hdr ip4_header;
	//ip4_header->ip_v = htons(4);
	//ip4_header->ip_hl = htons(5);
	//ip4_header->ip_len = htons(40);
	//ip4_header->ip_p = IPPROTO_TCP;
	//ip4_header->ip_off = htons(IP_DF);
	//ip4_header->ip_ttl = 48;
	//ip4_header->ip_src;
	//ip4_header->ip_dst;
	struct libnet_tcp_hdr tcp_header;
	//tcp_header->th_sport; 받은 패킷의 dest port
	//tcp_header->th_dport; 받은 패킷의 source port
	//tcp_header->th_seq; 받은 패킷의 ack
	//tcp_header->th_ack; 받은 seq+ tcp_len (total_len - 40)
	//tcp_header->th_off = htons(5);
	//tcp_header->th_flags = htons(TH_RST); or htons(TH_FIN)
	//tcp_header->th_win = 0;
	//tcp_header->th_sum = 0;
};
char* redir = "HTTP/1.1 302 Redirct\r\nLocation: http://warning.co.kr/i3.html\r\n\r\n"; 
char* fake = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Nov 2017 19:00:00 GMT\r\nServer: Apache\r\nContent-Length: 238\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html>\r\n  <head>\r\n    <title>Trapcard</title>\r\n  </head>\r\n  <body>\r\n   funny<p>\r\n  </body>\r\n</html>\r\n";

void Ip_hd_checksum(libnet_ipv4_hdr* ip_hd) {
	uint16_t *p = (uint16_t*)ip_hd;
	int len = 20;
	uint32_t chksum = 0;
	len >>= 1;
	ip_hd->ip_sum = 0;
	for(int i = 0; i<len;i++){
		chksum += *p++;
	}

	chksum = (chksum >> 16) +(chksum & 0xffff);
	chksum += (chksum >> 16);
	ip_hd->ip_sum = (~chksum & 0xffff);
}

void Tcp_checksum(struct rst_packet *rst_hd) {
	uint16_t *p = (uint16_t *)&(rst_hd->tcp_header);
	uint16_t *tempip;
	uint16_t datalen = (ntohs(rst_hd->ip4_header.ip_len)) - LIBNET_IPV4_H ;
	uint16_t len = datalen;
	uint32_t chksum = 0;
	len >>= 1;
	rst_hd->tcp_header.th_sum = 0;
	for(int i =0; i<len;i++) {
		chksum += *p++;
	}

	if(datalen % 2 == 1) {
		chksum += *p++ & 0x00ff;
	}
	tempip = (uint16_t *)(&rst_hd->ip4_header.ip_dst);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	tempip = (uint16_t *)(&rst_hd->ip4_header.ip_src);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	chksum += htons(6);
	chksum += htons(datalen);
	chksum = (chksum >> 16) +(chksum & 0xffff);
	chksum += (chksum >> 16);
	rst_hd->tcp_header.th_sum = (~chksum & 0xffff);
}


void make_rst(struct rst_packet *rst) {
	rst->eth_header.ether_type = htons(ETHERTYPE_IP);

	rst->ip4_header.ip_v = 4;
	rst->ip4_header.ip_hl = 5;
	rst->ip4_header.ip_len = htons(0x0068 + strlen(fake) - strlen(redir));
	rst->ip4_header.ip_ttl = 64;
	rst->ip4_header.ip_p = IPPROTO_TCP;
	rst->ip4_header.ip_sum = htons(0xabcd);
//	rst->ip4_header.ip_id = htons(0x9876);
	rst->ip4_header.ip_off = htons(IP_DF);
	rst->tcp_header.th_off = 5;
	rst->tcp_header.th_flags = TH_RST; //| TH_ACK;
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
	int flag;
	if(argc != 2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	struct rst_packet rst_p;

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		flag = -1;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr *)packet;
		eth->ether_type = ntohs(eth->ether_type);
		if(eth->ether_type == ETHERTYPE_IP){
//			printf("\nIt's IP\n");
			struct libnet_ipv4_hdr* ip4 = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H );
//			printf("ip 타입: %d\n", ip4->ip_p);
//			char ip_src[INET_ADDRSTRLEN];
//			char ip_dst[INET_ADDRSTRLEN];
//    		printf("ip_src : %s\n",inet_ntop(AF_INET, &ip4->ip_src, ip_src, INET_ADDRSTRLEN));
// 			printf("ip_des : %s\n",inet_ntop(AF_INET, &ip4->ip_dst, ip_dst, INET_ADDRSTRLEN));
			if(ip4->ip_p == IPPROTO_TCP){
//				printf("\nIt's TCP\n");
/*
				printf("\n_______________TCP packet _______________ \n");
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
				for(int i = ((header->len)/16)*16; i < header->len; i++) {
					printf("%02x ", ((uint8_t *)packet)[i]);
				}
*/
				//first check packet is http.request.
				struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
				uint16_t tcp_len = ntohs(ip4->ip_len) - LIBNET_IPV4_H;
				uint16_t tcp_payload_len = tcp_len - tcp->th_off*4;
				uint8_t *tcp_payload = (uint8_t *)packet + LIBNET_ETH_H + LIBNET_IPV4_H + tcp->th_off*4;
				printf("\nTCP Payload_len : %d\n", tcp_payload_len);
				if(tcp_payload_len !=  0 && memcmp(tcp_payload, get_str ,strlen(get_str)) == 0) {
					printf("\nIt's HTTP.request\n");
					flag = 1;
				}
				else {
					flag = 0;
				}
				if((tcp->th_flags & TH_ACK) != 0 && ((tcp->th_flags & TH_RST)==0) && flag == 0) {

					//Forward RST
					memcpy(rst_p.eth_header.ether_shost, eth->ether_shost, 6);
					memcpy(rst_p.eth_header.ether_dhost, eth->ether_dhost, 6);
					memcpy(&(rst_p.ip4_header.ip_src), &(ip4->ip_src), 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);
					memcpy(&rst_p.ip4_header.ip_tos, &ip4->ip_tos, 2);
					rst_p.ip4_header.ip_id, htons(ntohs(ip4->ip_id)+1);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_ack, &tcp->th_ack, 4);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_seq, 4);
					
					make_rst(&rst_p);
					rst_p.ip4_header.ip_len = htons(0x0028);

					Ip_hd_checksum(&(rst_p.ip4_header));
					Tcp_checksum(&rst_p);

					printf("Send Forward RST_TCP\n");
					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));

					//Backward RST
					memcpy(&rst_p.eth_header.ether_shost, &eth->ether_dhost, 6);
					memcpy(&rst_p.eth_header.ether_dhost, &eth->ether_shost, 6);
					memcpy(&rst_p.ip4_header.ip_src, &ip4->ip_dst, 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_src, 4);
					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_ack, 4);
					memset(&rst_p.tcp_header.th_ack, 0, 4);

//					memcpy(rst_p.ip4_header.th_ack, (tcp->th_seq + tcp_payload_len), 4);
//					rst_p.tcp_header.th_ack = tcp->th_seq;
					rst_p.ip4_header.ip_len = htons(0x0028);
					rst_p.ip4_header.ip_id, htons(ntohs(ip4->ip_id)+1);

					Ip_hd_checksum(&(rst_p.ip4_header));
					Tcp_checksum(&rst_p);
/*
					printf("______________________Backward RST packet______________________\n");
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

//					printf("size of rst_packet: %d\n", sizeof(struct rst_packet));
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
					for(int i = (sizeof(struct rst_packet)/16)*16; i < sizeof(struct rst_packet); i++) {
						printf("%02x ", ((uint8_t *)&rst_p)[i]);
					}
					printf("\n\n");
*/
					printf("Send Backward RST_TCP\n");
					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));
				}

				if(((tcp->th_flags & TH_RST)==0) && flag == 1) {
				//Forward RST
					memcpy(rst_p.eth_header.ether_shost, eth->ether_shost, 6);
					memcpy(rst_p.eth_header.ether_dhost, eth->ether_dhost, 6);
					memcpy(&(rst_p.ip4_header.ip_src), &(ip4->ip_src), 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);
					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);
					rst_p.tcp_header.th_seq = tcp->th_seq + (uint32_t)tcp_payload_len;
					memset(&rst_p.tcp_header.th_ack, 0, 4);
					make_rst(&rst_p);
					rst_p.ip4_header.ip_len = htons(0x0028);
					rst_p.ip4_header.ip_id, htons(ntohs(ip4->ip_id)+1);
					printf("Send Forward RST_HTTP\n");
					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));
/*
					//backward RST packet
					memcpy(rst_p.eth_header.ether_shost, eth->ether_dhost, 6);
					memcpy(rst_p.eth_header.ether_dhost, eth->ether_shost, 6);
					memcpy(&(rst_p.ip4_header.ip_src), &(ip4->ip_dst), 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_src, 4);
					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &tcp->th_ack, 4);
//					memcpy(&rst_p.tcp_header.th_ack, &tcp->th_ack, 4);
					memset(&rst_p.tcp_header.th_ack, 0, 4);
					make_rst(&rst_p);
					rst_p.ip4_header.ip_len = htons(0x0028);
					printf("Send Backward RST_HTTP\n");
					pcap_sendpacket(handle, (uint8_t*)&rst_p, sizeof(struct rst_packet));
*/
					//Backward FIN redirect.
					void* redir_p = malloc(sizeof(rst_packet) + strlen(fake));
					struct rst_packet* fin_p = (struct rst_packet *)redir_p;

					memcpy(fin_p->eth_header.ether_shost, eth->ether_dhost, 6);
					memcpy(fin_p->eth_header.ether_dhost, eth->ether_shost, 6);
					memcpy(&(fin_p->ip4_header.ip_src), &(ip4->ip_dst), 4);
					memcpy(&fin_p->ip4_header.ip_dst, &ip4->ip_src, 4);
					memcpy(&fin_p->tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&fin_p->tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&fin_p->tcp_header.th_seq, &tcp->th_ack, 4);
					fin_p->tcp_header.th_ack = htonl(ntohl(tcp->th_seq) + (uint32_t)tcp_payload_len);
					rst_p.ip4_header.ip_id, htons(ntohs(ip4->ip_id)+1);
//					memcpy(&fin_p->tcp_header.th_ack, &tcp->th_seq + tcp_payload_len, 4);
					make_rst(fin_p);
					fin_p->tcp_header.th_flags = (TH_FIN ^ TH_ACK); // ^ TH_PUSH ^ TH_ACK
					memcpy((redir_p + sizeof(rst_packet)),fake,strlen(fake));
					Ip_hd_checksum(&(fin_p->ip4_header));
					Tcp_checksum(fin_p);

					printf("Send Backward FIN_HTTP\n");
					pcap_sendpacket(handle, (uint8_t*)fin_p, sizeof(struct rst_packet) + strlen(fake) );

					/*
					printf("______________________Backward FIN Redirection packet______________________\n");
					printf("source mac: ");
					print_ether(fin_p->eth_header.ether_shost);
					printf("dst mac: ");
					print_ether(fin_p->eth_header.ether_dhost);
					printf("ether type : 0x%04x\n", fin_p->eth_header.ether_type);
					printf("ip_version(4) : %x\n", fin_p->ip4_header.ip_v);
					printf("ip_hl(5) : %x\n", fin_p->ip4_header.ip_hl);
					printf("ip_len(40) : %04x\n", fin_p->ip4_header.ip_len);
					printf("ack num: 0x%08x\n",ntohl(fin_p->tcp_header.th_ack));
					printf("seq num: 0x%08x\n",ntohl(fin_p->tcp_header.th_seq));


					for(int j = 0; j < (sizeof(rst_packet) + strlen(redir))/16 ; j++) {
						for(int i = 0; i < 8; i++) {
							printf("%02x ", ((uint8_t *)fin_p)[i+j*16]);
						}
						printf("  ");
						for(int i = 8; i < 16; i++) {
							printf("%02x ", ((uint8_t *)fin_p)[i+j*16]);
						}
						printf(" \n");
					}

					for(int i = ((sizeof(rst_packet) + strlen(redir))/16)*16; i < (sizeof(rst_packet) + strlen(redir)); i++) {
						printf("%02x ", ((uint8_t *)fin_p)[i]);
					}
					printf("\n\n");
					*/
				}
			}
		}
	}

	return 0;
}
