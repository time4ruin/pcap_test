#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct eth_header{
  u_char dst_mac[6];
  u_char src_mac[6];
  u_short prt_type;
};

struct ip_header{
  u_char ver4_hlen4; //version 4bit + header length 4bit
  u_char DSF; //Differentiated Serviced Field
  u_short totallen;
  u_short id;
  u_short fragoffset;
  u_char ttl; //Time to live
  u_char protocol;
  u_short hchecksum;
  u_char src_ip[4];
  u_char dst_ip[4];
}; //can be up to 40 optional bytes

struct tcp_header{
  u_short src_port;
  u_short dst_port;
  u_int seqnum;
  u_int acknum;
  u_short hlen4_flags12; //header length 4bit + flags 12bit
  u_short wsize; //window size
  u_short checksum;
  u_short urgent_pointer;
}; //can be up to 20 optional bytes

struct eth_header *eth;
struct ip_header *ip;
struct tcp_header *tcp;

void dump(const u_char* p, int len){
	/*
	for(int i = 0; i < len; i++){
		printf("%02x ", *(p+i));
		if((i & 0x0f) == 0x0f)
			printf("\n");
		}
	printf("\n");
	*/
	
	/* Ethernet Header */
	eth = (struct eth_header *)p;
	printf("Source MAC: ");
	for (int j = 0; j < 6; j++){
		printf("%02X", eth->src_mac[j]);
		if (j!=5) printf(":");
	}
	printf("\nDestination MAC: ");
	for (int j = 0; j < 6; j++){
		printf("%02X", eth->dst_mac[j]);
		if (j!=5) printf(":");
	}
	printf("\n");
	if (ntohs(eth->prt_type) == 0x0800){ // if IPv4 (0x0800 in little endian)
		p += 14;
		/* IP Header */
		ip = (struct ip_header *)p;
		printf("Source IP: ");
		for (int j = 0; j < 4; j++){
			printf("%d", ip->src_ip[j]);
			if (j!=3) printf(".");
		}
		printf("\nDestination IP: ");
		for (int j = 0; j < 4; j++){
			printf("%d", ip->dst_ip[j]);
			if (j!=3) printf(".");
		}
		printf("\n");
		if (ip->protocol == 0x06){ // if TCP
			p += ((ip->ver4_hlen4 & 0x0f) * 4);
			/* TCP Header */
			tcp = (struct tcp_header *)p;
			printf("Source Port: %d\n", ntohs(tcp->src_port));
			printf("Destination Port: %d\n", ntohs(tcp->dst_port));
			
			p += ((ntohs(tcp->hlen4_flags12) & 0xf000) >> 12) * 4; 
			/* Data */
			int Totallen = ntohs(ip->totallen);
			int IPlen = (ip->ver4_hlen4 & 0x0f) * 4;
			int TCPlen = ((ntohs(tcp->hlen4_flags12) & 0xf000) >> 12) * 4;

			int Datalen = Totallen - IPlen - TCPlen;
			if (Datalen > 32){
				for (int j = 0; j < 32; j++){
					printf("%02X ", *p);
				if ((j & 0x0f) == 0x0f){
					printf("\n");
					}
					p++;
				}
				printf("...\n");
			}
			else{
				for (int j = 0; j < Datalen; j++){
					printf("%02X ", *p);
					if ((j & 0x0f) == 0x0f){
						printf("\n");
					}
					p++;
				}
				printf("\n");
			}
		}
	}
	printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    dump(packet, header->caplen);
    //break;
  }

  pcap_close(handle);
  return 0;
}
