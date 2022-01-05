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
//spoof the ip 
#define SOURCE_IP "10.9.0.7"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "10.9.0.5"
 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 
// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

int main(){
    struct ip iphdr; // IPv4 header

    //==================
    // IP header
    //==================

    // IP protocol version (4 bits)
    iphdr.ip_v = 4;

    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct

    // Type of service (8 bits) - not using, zero it.
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons (IP4_HDRLEN);

    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;

    // Fragmentation bits - we are sending short packets below MTU-size and without 
    // fragmentation
    int ip_flags[4];

    // Reserved bit
    ip_flags[0] = 0;

    // "Do not fragment" bit
    ip_flags[1] = 0;

    // "More fragments" bit
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13) +  ip_flags[3]);

    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 128;

    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;

    // Source IP
    if (inet_pton (AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0) 
    {
        fprintf (stderr, "inet_pton() failed for source-ip with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        return -1;
    }

    // Destination IPv
    if (inet_pton (AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d" 
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        return -1;
    }

    // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // First, IP header.
    memcpy (packet, &iphdr, IP4_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
#if defined _WIN32
    dest_in.sin_addr.s_addr = iphdr.ip_dst;
#else
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
#endif

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    //
    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL,
#if defined _WIN32
		(const char*)
#endif
		&flagOne, // The above casting is important for Windows.
		sizeof (flagOne)) == -1) 
    {
        fprintf (stderr, "setsockopt() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        return -1;
    }

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, IP4_HDRLEN, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        return -1;
    }

  // Close the raw socket descriptor.
  close(sock);

  return 0;
}