#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <ifaddrs.h>
#include "raw.h"
#include "tcp_handshake.h"

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x08, 0x00, 0x27, 0xbb, 0x4e, 0xf6};
char src_mac[6] =	{0xdc, 0xa9, 0x04, 0x7c, 0x3c, 0x4e};

struct in_addr meu_ip;
in_addr_t target_ip;

union eth_buffer buffer_u;

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

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	target_ip = inet_addr(argv[2]);

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

	/* Obtem IP da interface de rede */
	obter_ip(ifName);

	/* End of configuration. Now we can send data using raw sockets. */

	/* Fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dst_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	buffer_u.cooked_data.payload.ip.ver = 0x45;
	buffer_u.cooked_data.payload.ip.tos = 0x00;
	buffer_u.cooked_data.payload.ip.len = htons(80);
	buffer_u.cooked_data.payload.ip.id = htons(0x00);
	buffer_u.cooked_data.payload.ip.off = htons(0x00);
	buffer_u.cooked_data.payload.ip.ttl = 50;
	buffer_u.cooked_data.payload.ip.proto = 0x01;
	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);
	memcpy(buffer_u.cooked_data.payload.ip.src, &meu_ip.s_addr, 4);
	buffer_u.cooked_data.payload.ip.dst[0] = 192;
	buffer_u.cooked_data.payload.ip.dst[1] = 168;
	buffer_u.cooked_data.payload.ip.dst[2] = 25;
	buffer_u.cooked_data.payload.ip.dst[3] = 9;
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));

	buffer_u.cooked_data.payload.icmp.icmphdr.type = 8;
	buffer_u.cooked_data.payload.icmp.icmphdr.code = 0;
	buffer_u.cooked_data.payload.icmp.icmphdr.un.echo.id = rand();
	buffer_u.cooked_data.payload.icmp.icmphdr.un.echo.sequence = rand();
	buffer_u.cooked_data.payload.icmp.icmphdr.checksum = 0;

	memcpy(&buffer_u.cooked_data.payload.bepis.bepishdr.target_ip, &target_ip, 4);
	// faltam 1476 bytes

	/* Fill ICMP payload */
	memcpy(buffer_u.cooked_data.payload.bepis.raw_data, pkt1, sizeof(pkt1));

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, 100, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	return 0;
}
