#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>


struct sniff_ethernet {
        u_char  ether_dhost[6];    /* destination host address */
        u_char  ether_shost[6];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniff_arp {
        u_short arp_htype; /*hardware type*/
        u_short arp_p; /*protocol*/
        u_char arp_hsize; /*hardware size*/
        u_char arp_psize; /*protocol size*/
        u_short arp_opcode; /*opcode*/
        u_char arp_smhost[6]; /*sender mac address*/
        struct in_addr arp_sip; /*sender ip address*/
        u_char arp_dmhost[6]; /*target mac address*/
        struct in_addr arp_dip; /*target ip address*/
};

int s_getIpAddress (const char * ifr, unsigned char * out) {  
    int sockfd;  
    struct ifreq ifrq;  
    struct sockaddr_in * sin;  
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    strcpy(ifrq.ifr_name, ifr);  
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
        perror( "ioctl() SIOCGIFADDR error");  
        return -1;  
    }  
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  
  
    close(sockfd);  
  
    return 4;  
} 

int main(int argc, char **argv) {
        char arp_packet[42];
        char *dev = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        struct in_addr addr;
        char *maskp;
        char *netp;

        bpf_u_int32 mask;
        bpf_u_int32 net;

        struct ifreq ifr;
        char ipstr[40];
        int s;

        if (argc == 2) {
                dev = argv[1];
        } else if (argc > 2) {
                fprintf(stderr, "error: unrecognized command-line options\n");
        } else {
                dev = pcap_lookupdev(errbuf);
                if (dev == NULL) {
                        fprintf(stderr, "Couldn't find default deviceL %s\n", errbuf);
                        exit(EXIT_FAILURE);
                }
        }

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }

        addr.s_addr = net;
        netp = inet_ntoa(addr);

        printf("IP : %s\n", netp);

        addr.s_addr = mask;
        maskp = inet_ntoa(addr);

        printf("MASK : %s\n", maskp);

        printf("Device: %s\n", dev);

    unsigned char addrs[4] = {0,};  
  
    if (s_getIpAddress(dev, addrs) > 0) {  
        printf("ip addr:=%d.%d.%d.%d", (int)addrs[0], (int)addrs[1], (int)addrs[2], (int)addrs[3]);  
    }  


}
