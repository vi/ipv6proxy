
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

#include <stdio.h>

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


#define MAXIFS 128

struct myinterface ifs[MAXIFS];
int nifs;


struct ip_map_entry {
    unsigned char ip[16];
    unsigned char mac[6];
    int ifindex;
};

#define MAXMAPSIZE 4096

struct ip_map_entry ip_map[MAXMAPSIZE];
int ip_map_size = 0;


// Add direct (without gateway) route to this address
int ipv6_route_op(int op, int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex) {
    struct in6_rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    
    rt.rtmsg_dst_len = prefix_len;
	rt.rtmsg_flags = ((prefix_len == 128) ? (RTF_UP|RTF_HOST) : RTF_UP);
	rt.rtmsg_metric = metric;
	
	rt.rtmsg_ifindex = 0;
	
	rt.rtmsg_ifindex = ifindex;
	
	memcpy(&rt.rtmsg_dst, addr, sizeof(struct in6_addr));
	
	if (op==0) {
	   return ioctl(sock_fd, SIOCADDRT, &rt);
	} else 
	if (op == 1) {
	   return ioctl(sock_fd, SIOCDELRT, &rt);
	} else return -1;
};


int del_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex) {
    return ipv6_route_op(1, sock_fd, addr, prefix_len, metric, ifindex);
}

// Add direct (without gateway) route to this address
int add_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex) {
    return ipv6_route_op(0, sock_fd, addr, prefix_len, metric, ifindex);
};

int my_if_nametoindex(int sock_fd, const char* devname) {
    struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));
	if(ioctl(sock_fd, SIOCGIFINDEX, &ifr)==-1) {
	    return -1;
	}
	return ifr.ifr_ifindex;
}

  /*
    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, devname, strlen(devname));
    if(ret==-1) perror("setsockopt SO_BINDTODEVICE");*/
    
    /*
    ret = add_ipv6_route(fd, (struct in6_addr*)"\xFD\x00\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x66\x66\x66\x66", 128, 1, ifindex);
    if(ret==-1) { perror("add_ipv6_route"); }
    
    ret = del_ipv6_route(fd, (struct in6_addr*)"\xFD\x00\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x66\x66\x66\x66", 128, 1, ifindex);
    if(ret==-1) { perror("del_ipv6_route"); }
    */

void printhex(unsigned char* buf, int n, FILE* f) {
    int i;
    for(i=0; i<n; ++i) {
        fprintf(f, "%02X", (int)buf[i]);
    }
}

// based on http://stackoverflow.com/a/14937171/266720
void checksum (void * buffer, int bytes, uint32_t *total, int finalize) {
   uint16_t * ptr;
   int        words;

   ptr   = (uint16_t *) buffer;
   words = (bytes + 1) / 2; // +1 & truncation on / handles any odd byte at end

   /*
    *   As we're using a 32 bit int to calculate 16 bit checksum
    *   we can accumulate carries in top half of DWORD and fold them in later
    */
   while (words--) *total += ntohs(*ptr++);

   if (finalize) {
       /*
        *   Fold in any carries
        *   - the addition may cause another carry so we loop
        */
       while (*total & 0xffff0000) *total = (*total >> 16) + (*total & 0xffff);
       *total = *total ^ 0xffff;
   }
}
// yourpkt->checksum = ~(checksum (buff, length));

// in icmp6.c
int open_packet_socket(int ifIndex);
int open_icmpv6_socket(int maxHops);
int get_rx(int sockpkt, unsigned char *msg, int maxsize);
int if_allmulti(const char *ifname, unsigned int state, unsigned char *savemacaddrhere);
// end of in icmp6.c

unsigned char buf[4096];


int main(int argc, char* argv[]) {
    
    if(argc<2 || !strcmp(argv[1], "--help")) {
        fprintf(stderr, "Usage: ipv6proxy eth0 wlan0 ...\n");
        return 1;
    }
    
    nifs = argc-1;
    
    int ret;
    int i;
    for(i=0; i<nifs; ++i){
        int fd_conf = socket( AF_INET6, SOCK_RAW, 58 /* ICMPv6 */ );
        if(fd_conf==-1) { perror("socket"); return 1; }
        
    
        const char *devname = argv[1+i];
        
        int ifindex = my_if_nametoindex(fd_conf, devname);
        if (ifindex == -1) { perror("get_interface_index"); };
        
        struct myinterface *ii = &ifs[i];
        
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
        for (i=0; i<nifs; ++i) {
            int fd = ifs[i].packetsock_fd;
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
        
        for(i=0; i<nifs; ++i) {
            int fd = ifs[i].packetsock_fd;
            if (fd!=-1 && FD_ISSET(fd, &rfds)) {
                ret = recv(fd, buf, sizeof buf, 0);
                if(ret<0) {
                    if(errno==EINTR || errno==EAGAIN) continue;
                    perror("recv");
                    close(ifs[i].packetsock_fd);
                    ifs[i].packetsock_fd = -1;
                }
                
                unsigned char *srcip = buf + ETH_HLEN+8;
                unsigned char *dstip = buf + ETH_HLEN+8+16;
                unsigned char *dstmac = buf ;
                unsigned char *srcmac = buf + 6;
                
                if (do_short_print) {
                    unsigned char icmp_type = buf[ETH_HLEN+8+32];
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
                        fprintf(stdout, " %s(%s)\n", ifs[i].name, itn);
                    } else {
                        fprintf(stdout, " %s(%d)\n", ifs[i].name, (int)icmp_type);
                    }
                    
                    fflush(stdout);
                }
                if (do_debug_print) {
                    fprintf(stdout, "%12s ",ifs[i].name);
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
                
                if(! !memcmp(buf+0, ifs[i].macaddr, 6)) {
                    // packet is being sent to somewhere
                }
                
                
                for (j=0; j<ip_map_size; ++j) {
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
                            fprintf(stderr, " to %s\n", ifs[i].name);
                            ip_map[j].ifindex = i;
                        }
                        break;
                    }
                }
                if (j==ip_map_size) {
                    // not found
                    if (ip_map_size == MAXMAPSIZE) {
                        // evict random entry
                        j = rand() % MAXMAPSIZE;
                        fprintf(stderr, "Evicting entry: ");
                            printhex(ip_map[j].ip, 16, stderr);
                        fprintf(stderr, " at %s mac ", ifs[ip_map[j].ifindex].name);
                            printhex(ip_map[j].mac, 6, stderr);
                        fprintf(stderr, "\n");
                    } else {
                        // add new entry
                        ++ip_map_size;
                    }
                    
                    ip_map[j].ifindex = i;
                    memcpy(ip_map[j].mac, srcmac, 6);
                    memcpy(ip_map[j].ip, srcip, 16);
                    
                    fprintf(stderr, "Adding entry: ");
                        printhex(ip_map[j].ip, 16, stderr);
                    fprintf(stderr, " at %s mac ", ifs[ip_map[j].ifindex].name);
                        printhex(ip_map[j].mac, 6, stderr);
                    fprintf(stderr, "\n");
                }
                
                
                // If we know the MAC for this destination IP, use it
                for (j=0; j<ip_map_size; ++j) {
                    if(!memcmp(ip_map[j].ip, dstip, 16)) {
                        memcpy(dstmac, ip_map[j].mac, 6);
                        break;
                    }
                }
                
                // TODO: send only to appropriate IF
                for (j=0; j < nifs; ++j) {
                    if (i==j) continue;
                    if (ifs[j].packetsock_fd == -1) continue;
                    
                    // substitude all mentions of source MAC address to new, our source address
                    {
                        int k;
                        for(k=0; k<nummentions; ++k) {
                            memcpy(buf+mac_mentions_indexes[k], ifs[j].macaddr, 6);
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
                    ret = send(ifs[j].packetsock_fd, buf, ret, 0);
                    if (ret==-1) {
                        if(errno==EINTR || errno==EAGAIN) goto again;
                        perror("send");
                        close(ifs[j].packetsock_fd);
                        ifs[j].packetsock_fd=-1;
                    }
                }
                
            } // if FD_ISSET
        } // for nifs
        usleep(1000);
    } // for(;;)

    return 0;
}
