#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Compute checksum
unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int main() {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];

    // Create a raw socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    // Set IP_HDRINCL
    int one = 1;
    const int *val = &one;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error");
        exit(-1);
    }

    // Construct the packet
    struct ip *ip = (struct ip *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct ip));
    char *data = buffer + sizeof(struct ip) + sizeof(struct udphdr);

    // IP header
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen("Hello, UDP!"));
    ip->ip_id = htons(54321);
    ip->ip_off = 0;
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0;
    ip->ip_src.s_addr = inet_addr("10.9.0.5");  // Spoofed source IP
    ip->ip_dst.s_addr = inet_addr("10.9.0.6");  // Destination IP

    // UDP header
    udp->uh_sport = htons(12345);  // Source port
    udp->uh_dport = htons(9090);   // Destination port
    udp->uh_ulen = htons(sizeof(struct udphdr) + strlen("Hello, UDP!"));
    udp->uh_sum = 0;  

    // UDP data
    strcpy(data, "Hello, UDP!");

    // Destination info
    sin.sin_family = AF_INET;
    sin.sin_port = udp->uh_dport;
    sin.sin_addr.s_addr = ip->ip_dst.s_addr;

    // Send the packet
    if (sendto(sd, buffer, ntohs(ip->ip_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    printf("Spoofed UDP packet sent successfully\n");
    return 0;
}
