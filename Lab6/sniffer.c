#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>    // Provides declarations for IP header

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    printf("Got a packet:\n");
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";

    bpf_u_int32 net;

    // use 1 to turn on promiscuous mode
    //handle = pcap_open_live("br-612ec73c878f", BUFSIZ, 0, 1000, errbuf);
    // use 0 to turn off promiscous mode
    handle = pcap_open_live("br-612ec73c878f", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
