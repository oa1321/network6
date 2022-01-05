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


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
    char buffer[2048];
    struct ip *ip_header = (struct ip *)(packet+sizeof(struct ethhdr)); 

    memcpy((char*)buffer, packet, 2048);

    struct ip* ip_spoof = (struct ip*)(buffer+sizeof(struct ethhdr));
    struct icmphdr* icmp_spoof = (struct icmphdr*)(buffer+sizeof(struct ethhdr) + (ip_header->ip_hl)*4);
    printf("%d\n", icmp_spoof->type);
    /*
    check the type of icmp(request)
    */
    if(icmp_spoof->type == 8){
        printf("%d\n", icmp_spoof->type);
        printf("%s\n",inet_ntoa(ip_header->ip_src));
        printf("%s\n",inet_ntoa(ip_header->ip_dst));
        /*
        change the src and the dest and set the ttl for kind of self debugging and also the type of icmp to 0(respond)
        */
        ip_spoof->ip_src = ip_header->ip_dst;
        ip_spoof->ip_dst = ip_header->ip_src;
        ip_spoof->ip_ttl = 200;
        icmp_spoof->type = 0;
        printf("%s\n",inet_ntoa(ip_spoof->ip_src));
        printf("%s\n",inet_ntoa(ip_spoof->ip_dst));
        struct sockaddr_in dest;
        /*
        create the socket 
        */
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(sock == -1){
            printf("problem is sock create");
        }
        const int flagOne = 1;
        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1){
            printf("problem is sock opt");
        }
        dest.sin_family = AF_INET;
        dest.sin_addr = ip_spoof->ip_dst;

        struct icmphdr* icmp_check = (struct icmphdr*)(buffer + (ip_header->ip_hl)*4);
        printf("%d\n", icmp_check->type);
    // sendto(sock, ip_spoof,2048, 0, (const struct sockaddr*)&dest, sizeof(dest));
    /*
        send the spoofed packet to the dst
        */
        printf("%ld\n",sendto(sock, ip_spoof,2048, 0, (const struct sockaddr*)&dest, sizeof(dest)));
        
        close(sock);
    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;
    //"br-a1d845e270ca"
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}
