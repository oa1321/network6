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
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/

struct ethhdr {
    u_char  ether_dhost[6];    
    u_char  ether_shost[6];   
    u_short ether_type;             
};
struct datas
{
    char da[40];
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sockaddr_in sniff_addr, Source, Dest;
    struct iphdr *ip_header = (struct iphdr *)(packet+sizeof(struct ethhdr)); 
    /*
    saves the data from the tcp header data part (ip len + tcp len(20))
    */
    struct datas *my_tcp = (struct datas *)(packet+sizeof(struct ethhdr)+(4 * ip_header->ihl)+20);
    memset(&Source, 0, sizeof(Source));
    Source.sin_addr.s_addr = ip_header->saddr;
    memset(&Dest, 0, sizeof(Dest));
    Dest.sin_addr.s_addr = ip_header->daddr;
    char SrcAddr[INET_ADDRSTRLEN];
    char DestAddr[INET_ADDRSTRLEN];
    /*
    prints what we got datas is a struct to save chars on from the packet
    */
    strcpy(SrcAddr, inet_ntoa(Source.sin_addr));
    strcpy(DestAddr, inet_ntoa(Dest.sin_addr));
    printf("%s \n", my_tcp->da); 
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //telnet port is 23
    char filter_exp[] = "tcp and port 23";
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