#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

/* Callback function for processing packets */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    const u_char *data;
    int ip_header_len, tcp_header_len, data_offset, data_len;

    // Extract IP header
    ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    ip_header_len = ip_header->ip_hl * 4;

    // Ensure it is TCP
    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
        tcp_header_len = tcp_header->th_off * 4;

        // Calculate data offset and length
        data_offset = 14 + ip_header_len + tcp_header_len;
        data_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;

        if (data_len > 0) {
            data = packet + data_offset;

            // Print data payload
            printf("Captured Data: ");
            for (int i = 0; i < data_len; i++) {
                printf("%c", isprint(data[i]) ? data[i] : '.'); // Replace non-printable characters with '.'
            }
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23"; // Telnet uses TCP port 23
    bpf_u_int32 net;

    // Open live pcap session
    handle = pcap_open_live("br-612ec73c878f", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Compile and set filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
