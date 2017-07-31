#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

struct sniff_arp {
        u_char  ether_dhost[6];    /* destination host address */
        u_char  ether_shost[6];    /* source host address */
        u_short ether_type;        /* IP? ARP? RARP? etc */

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

char *getMAC(const char *ip, struct sniff_arp * arp_packet){
        struct ifaddrs *ifaddr, *ifa;
        int family, s, i;
        char host[NI_MAXHOST];
        struct sockaddr *sdl;
        unsigned char *ptr;
        char *ifa_name;
        char *mac_addr = (char*)calloc(sizeof(char), 18);

        if (getifaddrs(&ifaddr) == -1) {
                perror("getifaddrs");
                return NULL;
        }

        //iterate to find interface name for given server_ip
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr != NULL) {
                        family = ifa->ifa_addr->sa_family;
                        if(family == AF_INET) {
                                s = getnameinfo(ifa->ifa_addr, (family == AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                                if (s != 0) {
                                        printf("getnameinfo() failed: %s\n", gai_strerror(s));
                                        return NULL;
                                }
                                if(strcmp(host, ip) == 0){
                                        ifa_name = ifa->ifa_name;
                                }
                        }
                }
        }

        //iterate to find corresponding ethernet address
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                family = ifa->ifa_addr->sa_family;
                if(family == PF_PACKET && strcmp(ifa_name, ifa->ifa_name) == 0) {
                        sdl = (struct sockaddr *)(ifa->ifa_addr);
                        ptr = (unsigned char *)sdl->sa_data;
                        ptr += 10;
                        for (i=0; i<=5; i++) {
                                sprintf(mac_addr, "%02x", *(ptr+i));
                                arp_packet->arp_smhost[i] = *(ptr+i);
                                arp_packet->ether_shost[i] = *(ptr+i);
                                arp_packet->ether_dhost[i] = 0xff;
                                printf("%02x\n", arp_packet->ether_dhost[i]);
                        }
                        break;
                }
        }
        freeifaddrs(ifaddr);
}

void create_arp (struct sniff_arp * arp_packet, char *sip, char *dip) {
        getMAC(sip, arp_packet);


}

int main(int argc, char **argv) {
        struct sniff_arp * arp_packet =  malloc(sizeof(struct sniff_arp));
        char *dev = NULL;
        char *sip = NULL;
        char *dip = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        bpf_u_int32 mask;
        bpf_u_int32 net;

        if (argc == 4) {
                dev = argv[1];
                sip = argv[2];
                dip = argv[3];
        } else if (argc > 4) {
                fprintf(stderr, "error: unrecognized command-line options\n");
                exit(EXIT_FAILURE);
        } else {
                fprintf(stderr, "error: do not matched argument\n");
                exit(EXIT_FAILURE);
        }

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }

        printf("Device: %s\n", dev);
        create_arp(arp_packet, sip, dip);
        


}
