#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>    
#include <arpa/inet.h>     

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); 
    
    printf("Got a packet:\n");
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    
    switch(ip_header->ip_p) {  
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            break;
        default:
            printf("   Protocol: Others\n");
            break;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    
    // Filter expression to capture ICMP packets between two specific hosts
    char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";

    bpf_u_int32 net;

    handle = pcap_open_live("br-b985f1959048", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Compile the filter expression into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Set the filter on the pcap handle
    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, -1, got_packet, NULL);
    
    // Close the handle when done
    pcap_close(handle);
    
    return 0;
}
