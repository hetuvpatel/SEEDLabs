#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PACKET_LEN 1500

// Compute checksum function
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

// Send spoofed ICMP echo reply
void send_echo_reply(struct ip *ip_header, struct icmp *icmp_header) {
    char buffer[PACKET_LEN];
    struct ip *reply_ip = (struct ip *)buffer;
    struct icmp *reply_icmp = (struct icmp *)(buffer + sizeof(struct ip));
    struct sockaddr_in dest_info;
    int enable = 1;

    // Construct IP header
    memset(buffer, 0, PACKET_LEN);
    reply_ip->ip_v = 4;
    reply_ip->ip_hl = 5;
    reply_ip->ip_tos = 0;
    reply_ip->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp));
    reply_ip->ip_id = htons(54321);
    reply_ip->ip_off = 0;
    reply_ip->ip_ttl = 64;
    reply_ip->ip_p = IPPROTO_ICMP;
    reply_ip->ip_sum = 0;
    reply_ip->ip_src = ip_header->ip_dst;
    reply_ip->ip_dst = ip_header->ip_src;

    // Construct ICMP header
    reply_icmp->icmp_type = ICMP_ECHOREPLY;
    reply_icmp->icmp_code = 0;
    reply_icmp->icmp_id = icmp_header->icmp_id;
    reply_icmp->icmp_seq = icmp_header->icmp_seq;
    reply_icmp->icmp_cksum = 0;
    reply_icmp->icmp_cksum = in_cksum((unsigned short *)reply_icmp, sizeof(struct icmp));

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket error");
        exit(1);
    }

    // Set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Set destination info
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = reply_ip->ip_dst;

    // Send the packet
    sendto(sock, buffer, ntohs(reply_ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

    close(sock);
    printf("Spoofed ICMP Echo Reply sent to %s\n", inet_ntoa(reply_ip->ip_dst));
}

// Packet processing callback function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct icmp *icmp_header = (struct icmp *)(packet + 14 + ip_header->ip_hl * 4);

    if (ip_header->ip_p == IPPROTO_ICMP && icmp_header->icmp_type == ICMP_ECHO) {
        printf("ICMP Echo Request detected from %s\n", inet_ntoa(ip_header->ip_src));
        send_echo_reply(ip_header, icmp_header);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] == icmp-echo";
    bpf_u_int32 net;

    // Open the network interface for packet capture
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Sniffing for ICMP Echo Requests...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
