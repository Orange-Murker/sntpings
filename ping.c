#include "assert.h"
#include "lodepng.h"
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define IMAGE "../image.png"

#define INTERFACE "interface_name"
#define SRC_IP "interface_mac"
#define DST_IP "2001:610:1908:a000:0000:0000:00d1:ffff"
const uint8_t dst_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define FRAME_SIZE 512

typedef struct {
	struct ip6_hdr ip6_header;
	struct icmp6_hdr icmp6_header;
} ping_packet_t;

typedef struct {
	struct iovec* rd;
	uint8_t* map;
	struct tpacket_req req;
	size_t current_frame;
} ring_t;

size_t sent_packets = 0;
unsigned char* image = 0;

static ping_packet_t get_ping_packet(struct in6_addr src_addr, struct in6_addr dst_addr)
{
	struct ip6_hdr ip6_header;
	struct icmp6_hdr icmp6_header;

	ip6_header.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
	// ICMP header length 8 bytes
	ip6_header.ip6_plen = htons(8);
	ip6_header.ip6_nxt = IPPROTO_ICMPV6;
	ip6_header.ip6_hops = 255;
	ip6_header.ip6_src = src_addr;
	ip6_header.ip6_dst = dst_addr;

	icmp6_header.icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_header.icmp6_code = 0;
	// TODO: Maybe add checksum
	icmp6_header.icmp6_cksum = 0;

	icmp6_header.icmp6_id = htons(0);
	icmp6_header.icmp6_seq = htons(0);

	ping_packet_t ping_packet = {
		.ip6_header = ip6_header,
		.icmp6_header = icmp6_header,
	};

	return ping_packet;
}

static int setup_ring(int fd, ring_t* ring, uint32_t frame_num)
{
	memset(ring, 0, sizeof(ring_t));

	int packet_version = TPACKET_V2;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &packet_version, sizeof(packet_version)) < 0) {
		perror("Could not setsockopt PACKET_VERSION");
		return EXIT_FAILURE;
	}

	struct tpacket_req req = ring->req;
	// Maximum possible block size
	// <block size> = <pagesize> << <max-order>
	assert(FRAME_SIZE <= getpagesize());
	req.tp_block_size = getpagesize() << 11;
	req.tp_block_nr = ((frame_num * FRAME_SIZE) + (req.tp_block_size - 1)) / req.tp_block_size;
	req.tp_frame_size = FRAME_SIZE;
	req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
	printf("Requested %dx %d byte frames\n", frame_num, FRAME_SIZE);
	printf("Allocating %dx %d byte frames in a %dx %d byte blocks (%d bytes wasted)\n", req.tp_frame_nr, req.tp_frame_size, req.tp_block_nr, req.tp_block_size, req.tp_block_nr * req.tp_block_size - frame_num * FRAME_SIZE);

	if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
		perror("Could not setsockopt PACKET_TX_RING");
		return EXIT_FAILURE;
	}

	ring->map = mmap(0, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (ring->map == MAP_FAILED) {
		perror("Could not mmap ring");
		return EXIT_FAILURE;
	}

	ring->rd = malloc(req.tp_block_nr * sizeof(*ring->rd));
	assert(ring->rd);
	for (size_t i = 0; i < req.tp_block_nr; i++) {
		ring->rd[i].iov_base = ring->map + (i * req.tp_block_size);
		ring->rd[i].iov_len = req.tp_block_size;
	}

	ring->req = req;

	return EXIT_SUCCESS;
}

static int setup_socket(int* fd)
{
	*fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (*fd < 0) {
		perror("Could not open socket");
		return EXIT_FAILURE;
	}

	// int en = 1;
	// if (setsockopt(*fd, SOL_PACKET, PACKET_QDISC_BYPASS, &en, sizeof(en)) < 0) {
	// 	perror("Could not setsockopt PACKET_QDISC_BYPASS");
	// 	return EXIT_FAILURE;
	// }

	return EXIT_SUCCESS;
}

static int bind_socket(int fd, struct sockaddr_ll* sockaddr)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", INTERFACE);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("Could not get device index");
		return EXIT_FAILURE;
	}
	printf("Using device index %d\n", ifr.ifr_ifindex);


	memset(sockaddr, 0, sizeof(struct sockaddr_ll));

	sockaddr->sll_family = AF_PACKET;
	sockaddr->sll_protocol = htons(ETH_P_IPV6);
	sockaddr->sll_ifindex = ifr.ifr_ifindex;
	sockaddr->sll_halen = ETH_ALEN;

	for(size_t i = 0; i < 6; i++) {
		sockaddr->sll_addr[i] = dst_mac[i];
	}

	if (bind(fd, (struct sockaddr*)sockaddr, sizeof(struct sockaddr_ll)) < 0) {
		perror("Could not bind socket");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void cleanup(int fd, ring_t ring)
{
	munmap(ring.map, ring.req.tp_block_size * ring.req.tp_block_nr);
	free(ring.rd);
	close(fd);
	free(image);
}

static int send_data(int fd, ring_t* ring, uint8_t* data, size_t len, bool copy)
{
	uint8_t* frame_start = ring->map + ring->current_frame * FRAME_SIZE;
	struct tpacket2_hdr* packet_header = (struct tpacket2_hdr*)frame_start;
	uint8_t* packet_data = frame_start + TPACKET_ALIGN(sizeof(struct tpacket2_hdr));

	struct pollfd pfd;
	pfd.fd = fd;
	pfd.revents = 0;
	pfd.events = POLLOUT;

	while (packet_header->tp_status != TP_STATUS_AVAILABLE) {
		if (poll(&pfd, 1, 1000) < 0) {
			perror("Could not poll for available frames");
			return EXIT_FAILURE;
		}
	}

	packet_header->tp_len = len;
	packet_header->tp_status = TP_STATUS_SEND_REQUEST;

	if (copy) {
		memcpy(packet_data, data, len);
	}

	ring->current_frame = (ring->current_frame + 1) % ring->req.tp_frame_nr;
	sent_packets++;

	return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	int err;
	int fd;
	ring_t ring;
	struct sockaddr_ll sockaddr;
	struct ifreq ifr;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;

	uint16_t x_start = 1000;
	uint16_t y_start = 500;

	uint32_t width, height;
	err = lodepng_decode32_file(&image, &width, &height, IMAGE);
	if (err) {
		printf("Lodepng error %u: %s\n", err, lodepng_error_text(err));
		exit(EXIT_FAILURE);
	}
	uint32_t image_size = width * height;
	pid_t pid;

	pid = fork();

	if (pid == 0) {
		pid = fork();
		if (pid == 0) {
			pid = fork();
		}
	}

	if ((err = inet_pton(AF_INET6, SRC_IP, &src_addr)) < 1) {
		perror("Could not convert the source address");
		exit(err);
	}

	if ((err = inet_pton(AF_INET6, DST_IP, &dst_addr)) < 1) {
		perror("Could not convert the destination address");
		exit(err);
	}

	if ((err = setup_socket(&fd))) {
		exit(err);
	}

	if ((err = setup_ring(fd, &ring, image_size))) {
		exit(err);
	}

	if ((err = bind_socket(fd, &sockaddr))) {
		exit(err);
	}

	bool first = true;
	while (1) {
		for (uint16_t y = 0; y < height; y++) {
			for (uint16_t x = 0; x < width; x++) {
				size_t i = x + y * height;

				dst_addr.s6_addr16[4] = htons(x_start + x);
				dst_addr.s6_addr16[5] = htons(y_start + y);

				size_t pixel_start = y * width * 4 + x * 4;

				uint8_t r = image[pixel_start];
				uint8_t g = image[pixel_start + 1];
				uint8_t b = image[pixel_start + 2];
				uint8_t a = image[pixel_start + 3];

				dst_addr.s6_addr[12] = b;
				dst_addr.s6_addr[13] = g;
				dst_addr.s6_addr[14] = r;
				dst_addr.s6_addr[15] = a;

				ping_packet_t ping_packet = get_ping_packet(src_addr, dst_addr);
				// Do not copy the data to the ring buffer again
				// This can only work if the image perfectly fits into the size of the allocated buffer
				if ((err = send_data(fd, &ring, (uint8_t*)&ping_packet, sizeof(ping_packet), first))) {
					exit(err);
				}
			}
		}

		if ((err = sendto(fd, NULL, 0, 0, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_ll))) < 0) {
			perror("sendto failed");
			exit(err);
		}

		first = false;

		printf("PID: %u Sent: %ld packets Ring frame: %lu\n", pid, sent_packets, ring.current_frame);
	}

	cleanup(fd, ring);
}
