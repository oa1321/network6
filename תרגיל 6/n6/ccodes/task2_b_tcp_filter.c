#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "headers.h"
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>


struct ethhdr {
    u_char  ether_dhost[6];    
    u_char  ether_shost[6];   
    u_short ether_type;             
};

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
we print the src and dst ip 
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sockaddr_in sniff_addr, Source, Dest;
    printf("Got a packet\n");
    struct iphdr *ip_header = (struct iphdr *)(packet+sizeof(struct ethhdr)); 
    memset(&Source, 0, sizeof(Source));
    Source.sin_addr.s_addr = ip_header->saddr;
    memset(&Dest, 0, sizeof(Dest));
    Dest.sin_addr.s_addr = ip_header->daddr;
    char SrcAddr[INET_ADDRSTRLEN];
    char DestAddr[INET_ADDRSTRLEN];
    strcpy(SrcAddr, inet_ntoa(Source.sin_addr));
    strcpy(DestAddr, inet_ntoa(Dest.sin_addr));
    printf("Source: %s   ", SrcAddr);  
    printf("Dest: %s\n", DestAddr);   
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    /*
    as in the syntex of BPF
    */
    char filter_exp[] = "tcp and dst portrange 10-100";
    bpf_u_int32 net;
    // Step 1: Open live pcap session on NIC with name eth3.
    // Students need to change "eth3" to the name found on their own
    // machines (using ifconfig). The interface to the 10.9.0.0/24
    // network has a prefix "br-" (if the container setup is used).

    handle = pcap_open_live("br-a1d845e270ca", BUFSIZ, 1, 1000, errbuf);
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
    }
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap