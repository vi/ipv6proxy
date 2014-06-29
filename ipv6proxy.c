
#define _GNU_SOURCE // memmem
#include <string.h>

#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <stdio.h>

#include "util.h"

int do_debug_print = 0;
int do_short_print = 1;

#define ETH_HLEN  14


struct myinterface {
    const char* name;
    int ifindex;
    int flags;
    unsigned char macaddr[6];
    int packetsock_fd;
    int prevallmulti;
};


#define MAX_INTERFACES 128
#define MAX_IPMAP_SIZE 4096

struct myinterface interfaces[MAX_INTERFACES];
int n_interfaces;


struct ip_map_entry {
    unsigned char ip[16];
    unsigned char mac[6];
    int ifindex;
    int routeadded;
};


struct ip_map_entry ip_map[MAX_IPMAP_SIZE];
int n_ip_map = 0;


unsigned char buf[4096];


int main(int argc, char* argv[]) {
    
    if(argc<2 || !strcmp(argv[1], "--help")) {
        fprintf(stderr, "Usage: ipv6proxy eth0 wlan0 ...\n");
        return 1;
    }
    
    n_interfaces = argc-1;
    
    int ret;
    int i;
    int fd_conf = socket( AF_INET6, SOCK_RAW, 58 /* ICMPv6 */ );
    for(i=0; i<n_interfaces; ++i){
        if(fd_conf==-1) { perror("socket"); return 1; }
        
    
        const char *devname = argv[1+i];
        
        int ifindex = my_if_nametoindex(fd_conf, devname);
        if (ifindex == -1) { perror("get_interface_index"); };
        
        struct myinterface *ii = &interfaces[i];
        
        ii->name = devname;
        ii->ifindex = ifindex;
        ii->prevallmulti = if_allmulti(devname, 1, ii->macaddr);
        ii->packetsock_fd = open_packet_socket(ifindex);
        if(ii->packetsock_fd < 0) return 1;
    }
        
    
    for(;;) {
        fd_set rfds;
        int maxfd = 0;
        FD_ZERO(&rfds);
        for (i=0; i<n_interfaces; ++i) {
            int fd = interfaces[i].packetsock_fd;
            if (fd!=-1) {
                FD_SET(fd, &rfds);
                if(maxfd < fd) maxfd=fd;
            }
        }
        
        ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
        
        if(ret==-1) {
            if(errno==EINTR||errno==EAGAIN)continue;
            perror("select");
            return 1;
        }
        
        for(i=0; i<n_interfaces; ++i) {
            int fd = interfaces[i].packetsock_fd;
            if (fd!=-1 && FD_ISSET(fd, &rfds)) {
                ret = recv(fd, buf, sizeof buf, 0);
                if(ret<0) {
                    if(errno==EINTR || errno==EAGAIN) continue;
                    perror("recv");
                    close(interfaces[i].packetsock_fd);
                    interfaces[i].packetsock_fd = -1;
                }
                
                unsigned char *srcip = buf + ETH_HLEN+8;
                unsigned char *dstip = buf + ETH_HLEN+8+16;
                unsigned char *dstmac = buf ;
                unsigned char *srcmac = buf + 6;
                
                unsigned char icmp_type = buf[ETH_HLEN+8+32];
                if (do_short_print) {
                    const char* itn = NULL;
                    
                    switch(icmp_type) {
                        case 1: itn="DestUnr"; break;
                        case 2: itn="PTooBig"; break;
                        case 3: itn="TExceed"; break;
                        case 4: itn="ParamProblem"; break;
                        case 128: itn="EchoReq"; break;
                        case 129: itn="EchoRepl"; break;
                        case 130: itn="MLQuery"; break;
                        case 131: itn="MLReport"; break;
                        case 132: itn="MLDone"; break;
                        case 133: itn="RouSolic"; break;
                        case 134: itn="RouAdv"; break;
                        case 135: itn="NeigSol"; break;
                        case 136: itn="NeighAdv"; break;
                        case 137: itn="Redirect"; break;
                        case 138: itn="RouterRenumbering"; break;
                        case 139: itn="IcmpNIQ"; break;
                        case 140: itn="IcmpNIR"; break;
                        case 141: itn="InvNeighSol"; break;
                        case 142: itn="InvNeighAdv"; break;
                        case 143: itn="MLDv2report"; break;
                        case 144: itn="HAADRq"; break;
                        case 145: itn="HAADReply"; break;
                        case 146: itn="MobilePrefixSol"; break;
                        case 147: itn="MobilePrefixAdv"; break;
                        case 148: itn="CertPathSol"; break;
                        case 149: itn="CertPathAdv"; break;
                        case 151: itn="MCRouterAdv"; break;
                        case 152: itn="MCRouterSol"; break;
                        case 153: itn="MCRouterTerm"; break;
                        case 155: itn="RPLConMsg"; break;
                    }
                    
                    printhex(srcip,16,stdout); fprintf(stdout, ":"); printhex(srcmac,6,stdout);
                    fprintf(stdout, " -> ");
                    printhex(dstip,16,stdout); fprintf(stdout, ":"); printhex(dstmac,6,stdout);
                    
                    if (itn) {
                        fprintf(stdout, " %s(%s)\n", interfaces[i].name, itn);
                    } else {
                        fprintf(stdout, " %s(%d)\n", interfaces[i].name, (int)icmp_type);
                    }
                    
                    fflush(stdout);
                }
                if (do_debug_print) {
                    fprintf(stdout, "%12s ",interfaces[i].name);
                    int i;
                    for(i=0; i<ret; ++i) {
                        if (i==6 || i==12 || 
                            i==ETH_HLEN || i==ETH_HLEN+6 ||
                            i==ETH_HLEN+7 || i==ETH_HLEN+8 ||
                            i==ETH_HLEN+8+16 || i==ETH_HLEN+8+32) fprintf(stdout, " ");
                        fprintf(stdout, "%02x", buf[i]);
                    }
                    fprintf(stdout, "\n");
                    fflush(stdout);
                    
                }
                
                int j;
                
                // tricky trick: find all mentions of the source MAC address to be overwritten
                const int maxmentions=10;
                int mac_mentions_indexes[maxmentions];
                int nummentions=0;
                
                int current_offset = 0;
                for(;nummentions<maxmentions && current_offset < ret-5;){
                    unsigned char* q = (unsigned char*)
                                memmem(buf+current_offset, ret-current_offset,
                                       buf+6, 6);
                    if(!q)break;
                    int offset = q-buf;
                    current_offset = offset+6;
                    
                    //fprintf(stderr, "Found mention %d in %d bytes packet af offset %d\n", nummentions, ret, offset);
                    mac_mentions_indexes[nummentions++] = offset;
                }
                //fprintf(stderr, ".\n");
                
                if(! !memcmp(buf+0, interfaces[i].macaddr, 6)) {
                    // packet is being sent to somewhere
                }
                
                
                for (j=0; j<n_ip_map; ++j) {
                    if(!memcmp(ip_map[j].ip, srcip, 16)) {
                        if (! !memcmp(ip_map[j].mac, srcmac, 6)) {
                            fprintf(stderr, "Updating mac for ");
                                printhex(srcip, 16, stderr);
                            fprintf(stderr, " to ");
                                printhex(srcmac, 6, stderr);
                            fprintf(stderr, "\n");
                            memcpy(ip_map[j].mac, srcmac, 6);
                        }
                        if (ip_map[j].ifindex != i) {
                            fprintf(stderr, "Updating network interface for ");
                                printhex(srcip, 16, stderr);
                            fprintf(stderr, " to %s\n", interfaces[i].name);
                            ip_map[j].ifindex = i;
                        }
                        //if (icmp_type == 136) {
                        /*    if (!ip_map[j].routeadded) {
                                // Neighbour advertisment => add explicit route
                                ip_map[j].routeadded = 1;
                                fprintf(stderr, "Adding a route for ");
                                    printhex(srcip, 16, stderr);
                                int rret = add_ipv6_route(fd_conf, (struct in6_addr *)srcip, 128, 1, interfaces[i].ifindex);
                                if (rret==-1) fprintf(stderr, " (fail)");
                                fprintf(stderr, "\n");
                            }*/
                        //}
                        break;
                    }
                }
                if (j==n_ip_map) {
                    // not found
                    if (n_ip_map == MAX_IPMAP_SIZE) {
                        // evict random entry
                        j = rand() % MAX_IPMAP_SIZE;
                        fprintf(stderr, "Evicting entry: ");
                            printhex(ip_map[j].ip, 16, stderr);
                        fprintf(stderr, " at %s mac ", interfaces[ip_map[j].ifindex].name);
                            printhex(ip_map[j].mac, 6, stderr);
                        fprintf(stderr, "\n");
                    } else {
                        // add new entry
                        ++n_ip_map;
                    }
                    
                    ip_map[j].ifindex = i;
                    memcpy(ip_map[j].mac, srcmac, 6);
                    memcpy(ip_map[j].ip, srcip, 16);
                    ip_map[j].routeadded = 0;
                    
                    fprintf(stderr, "Adding entry: ");
                        printhex(ip_map[j].ip, 16, stderr);
                    fprintf(stderr, " at %s mac ", interfaces[ip_map[j].ifindex].name);
                        printhex(ip_map[j].mac, 6, stderr);
                    
                    //if (icmp_type == 136) {
                        // Neighbour advertisment => add explicit route
                    //     add_ipv6_route(fd_conf, (struct in6_addr *)srcip, 128, 1, interfaces[i].ifindex);
                    //    ip_map[j].routeadded = 1;
                     //   fprintf(stderr, " with a route");
                    //}
                    fprintf(stderr, "\n");
                    maybe_add_route(srcip, interfaces[i].name);
                }
                
                
                // If we know the MAC for this destination IP, use it
                for (j=0; j<n_ip_map; ++j) {
                    if(!memcmp(ip_map[j].ip, dstip, 16)) {
                        memcpy(dstmac, ip_map[j].mac, 6);
                        break;
                    }
                }
                
                // TODO: send only to appropriate IF
                for (j=0; j < n_interfaces; ++j) {
                    if (i==j) continue;
                    if (interfaces[j].packetsock_fd == -1) continue;
                    
                    // substitude all mentions of source MAC address to new, our source address
                    {
                        int k;
                        for(k=0; k<nummentions; ++k) {
                            memcpy(buf+mac_mentions_indexes[k], interfaces[j].macaddr, 6);
                        }
                    }
                    // fixup the checksum
                    {
                        //unsigned long old_checksum = buf[ETH_HLEN+8+32 + 2]*256 + buf[ETH_HLEN+8+32 + 3];
                        uint32_t new_checksum = 0;
                        buf[ETH_HLEN+8+32 + 2] = 0;
                        buf[ETH_HLEN+8+32 + 3] = 0;
                        
                        checksum(srcip   , 16,   &new_checksum, 0);
                        checksum(dstip   , 16,   &new_checksum, 0);
                        int len = ret - (ETH_HLEN+8+32);
                        unsigned char lenbuf[4]; lenbuf[0]=0; lenbuf[1]=0; lenbuf[2]=len>>8; lenbuf[3]=len&0xFF;
                        checksum(lenbuf,               4,   &new_checksum, 0); // len
                        checksum("\x00\x00\x00\x3A",   4,   &new_checksum, 0); // next header type
                        checksum(buf + ETH_HLEN+8+32,  len, &new_checksum, 1);
                        
                        buf[ETH_HLEN+8+32 + 2] = new_checksum>>8;
                        buf[ETH_HLEN+8+32 + 3] = new_checksum&0xFF;
                        
                        //printf("oc=%04lx nc=%04x ",old_checksum, new_checksum);
                    }
                    
                    again:
                    ret = send(interfaces[j].packetsock_fd, buf, ret, 0);
                    if (ret==-1) {
                        if(errno==EINTR || errno==EAGAIN) goto again;
                        perror("send");
                        close(interfaces[j].packetsock_fd);
                        interfaces[j].packetsock_fd=-1;
                    }
                }
                
            } // if FD_ISSET
        } // for n_interfaces
        usleep(1000);
    } // for(;;)

    return 0;
}
