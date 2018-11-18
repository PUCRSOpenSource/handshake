#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <ifaddrs.h>
#include "raw.h"

#define PROTO_UDP	17
#define PROTO_ICMP	1
#define DST_PORT	8000

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0xdc, 0xa9, 0x04, 0x7c, 0x3c, 0x4e};
char src_mac[6] =	{0x08, 0x00, 0x27, 0xbb, 0x4e, 0xf6};

struct in_addr meu_ip;
in_addr_t client_ip;

union eth_buffer buffer_u;

void envia_reply(union eth_buffer* buffer_u, char ifName[]){
	struct ifreq if_idx, if_mac, ifopts;
	struct sockaddr_ll socket_address;
	int sockfd;

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u->raw_data, 100, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");
	close(sockfd);
}

void desencapsula_e_envia_tcp(union eth_buffer buffer_tcp, char ifName[])
{
	printf("%u\n", ntohl(meu_ip.s_addr));

	memcpy(buffer_tcp.cooked_data.payload.ip.src, &meu_ip.s_addr, 4);

	buffer_tcp.cooked_data.payload.ip.dst[0] = 192;
	buffer_tcp.cooked_data.payload.ip.dst[1] = 168;
	buffer_tcp.cooked_data.payload.ip.dst[2] = 25;
	buffer_tcp.cooked_data.payload.ip.dst[3] = 3;
	buffer_tcp.cooked_data.payload.ip.proto = 0x06;

	char* p = (char *)&buffer_tcp.cooked_data.payload.icmp.icmphdr + sizeof(struct icmp_hdr);
	memcpy(buffer_tcp.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr), p, 40);

	//printf("source: %d\n", ntohs(buffer_tcp.cooked_data.payload.tcp.tcphdr.source));
	//printf("dest: %d\n", ntohs(buffer_tcp.cooked_data.payload.tcp.tcphdr.dest));
	//printf("seq: %d\n", buffer_tcp.cooked_data.payload.tcp.tcphdr.seq);
	//printf("ack_seq: %d\n", buffer_tcp.cooked_data.payload.tcp.tcphdr.ack_seq);

	envia_reply(&buffer_tcp, ifName);
}

void obter_ip(char ifName[])
{
	struct ifaddrs* addrs;
	getifaddrs(&addrs);
	struct ifaddrs* tmp = addrs;

	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
			if (strcmp(tmp->ifa_name, ifName) == 0)
				meu_ip = pAddr->sin_addr;
		}
		tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);
}


int main(int argc, char *argv[])
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	client_ip = inet_addr(argv[2]);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Obtem IP da interface de rede */
	obter_ip(ifName);

	/* End of configuration. Now we can receive data using raw sockets. */


	while (1){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) && memcmp(buffer_u.cooked_data.payload.ip.src, &client_ip, 4) == 0){
			if (buffer_u.cooked_data.payload.ip.proto == PROTO_ICMP && buffer_u.cooked_data.payload.icmp.icmphdr.type == 8 && buffer_u.cooked_data.payload.icmp.icmphdr.code == 0){
				printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
						numbytes,
						buffer_u.cooked_data.payload.ip.src[0],buffer_u.cooked_data.payload.ip.src[1],
						buffer_u.cooked_data.payload.ip.src[2],buffer_u.cooked_data.payload.ip.src[3],
						buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
						buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
						buffer_u.cooked_data.payload.ip.proto
					);
				desencapsula_e_envia_tcp(buffer_u, ifName);

				uint8_t aux;
				aux = buffer_u.cooked_data.payload.ip.src[0];
				buffer_u.cooked_data.payload.ip.src[0] = buffer_u.cooked_data.payload.ip.dst[0];
				buffer_u.cooked_data.payload.ip.dst[0] = aux;

				aux = buffer_u.cooked_data.payload.ip.src[1];
				buffer_u.cooked_data.payload.ip.src[1] = buffer_u.cooked_data.payload.ip.dst[1];
				buffer_u.cooked_data.payload.ip.dst[1] = aux;

				aux = buffer_u.cooked_data.payload.ip.src[2];
				buffer_u.cooked_data.payload.ip.src[2] = buffer_u.cooked_data.payload.ip.dst[2];
				buffer_u.cooked_data.payload.ip.dst[2] = aux;

				aux = buffer_u.cooked_data.payload.ip.src[3];
				buffer_u.cooked_data.payload.ip.src[3] = buffer_u.cooked_data.payload.ip.dst[3];
				buffer_u.cooked_data.payload.ip.dst[3] = aux;

				buffer_u.cooked_data.payload.icmp.icmphdr.type = 0;
				buffer_u.cooked_data.payload.icmp.icmphdr.code = 0;
				buffer_u.cooked_data.payload.icmp.icmphdr.un.echo.id = rand();
				buffer_u.cooked_data.payload.icmp.icmphdr.un.echo.sequence = rand();
				buffer_u.cooked_data.payload.icmp.icmphdr.checksum = 0;

				envia_reply(&buffer_u, ifName);
			}
		}
	}

	return 0;
}
