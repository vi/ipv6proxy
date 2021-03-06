
#define _GNU_SOURCE // memmem
#include <string.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/filter.h>
#include <netpacket/packet.h>

#include <stddef.h>

#include <stdio.h>


#include "util.h"
#include "popen_arr.h"
#include "scripts.h"

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

void render_hex(char* str, int strlen, const unsigned char* buf, int n, int as_ipv6_address) {
    char* p = str;
    int i;
    for (i=0; i<n; ++i) {
        if(as_ipv6_address && i>0 && i%2==0) *p++ = ':';
        sprintf(p, "%02x", (int)buf[i]);
        p+=2;
    }
    assert(p-str < strlen);
    *p=0;
}

void printhex(const unsigned char* buf, int n, FILE* f) {
    char tmpbuf[512];
    render_hex(tmpbuf, sizeof tmpbuf, buf, n, 0);
    fprintf(f, "%s", tmpbuf);
}
void printipv6(const unsigned char* ipv6, FILE* f) {
    char tmpbuf[64];
    render_hex(tmpbuf, sizeof tmpbuf, ipv6, 16, 1);
    fprintf(f, "%s", tmpbuf);
}

// based on http://stackoverflow.com/a/14937171/266720
void checksum (const void * buffer, int bytes, uint32_t *total, int finalize) {
   const uint16_t * ptr;
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


void call_route_script(const char* script_code, const unsigned char *srcip, const char *ifname) {
    if (options & NOROUTES) return;
    
    char ip6buf[16*2+16];
    render_hex(ip6buf, sizeof ip6buf, srcip, 16, 1);
    
    const char* argv[] = {"sh", "-c", script_code, "--", ip6buf, ifname, NULL};
    int pid = popen2_arr_p(NULL, argv[0], argv, NULL, "");
    int ret;
    int status;
    do { ret = waitpid(pid, &status, 0); } while(ret==-1 && (errno==EINTR || errno==EAGAIN));
}

void maybe_add_route(const unsigned char *srcip, const char *ifname) {
    return call_route_script((const char*)script_maybe_add_route, srcip, ifname);
}
void maybe_del_route(const unsigned char *srcip, const char *ifname) {
    return call_route_script((const char*)script_maybe_del_route, srcip, ifname);
}

#define DECALRE_srcip_dstip_srcmac_dstmac_FROM_buf \
    const unsigned char *srcip = buf + ETH_HLEN+8;    (void)srcip; \
    const unsigned char *dstip = buf + ETH_HLEN+8+16; (void)dstip;\
    const unsigned char *dstmac = buf ;               (void)dstmac; \
    const unsigned char *srcmac = buf + 6;            (void)srcmac;

void debug_print(enum debugmode_t debug_print_mode, unsigned const char *buf, int received_length, const char* current_interface_name) {
    unsigned char icmp_type = buf[ETH_HLEN+8+32];
    DECALRE_srcip_dstip_srcmac_dstmac_FROM_buf;
    if (debug_print_mode & D_SHORT) {
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
        
        printipv6(srcip,stdout); fprintf(stdout, " @ "); printhex(srcmac,6,stdout);
        fprintf(stdout, " -> ");
        printipv6(dstip,stdout); fprintf(stdout, " @ "); printhex(dstmac,6,stdout);
        
        if (itn) {
            fprintf(stdout, " %s(%s)\n", current_interface_name, itn);
        } else {
            fprintf(stdout, " %s(%d)\n", current_interface_name, (int)icmp_type);
        }
        
        fflush(stdout);
    }
    if (debug_print_mode & D_PACKET_DUMPS) {
        fprintf(stdout, "%12s ",current_interface_name);
        int i;
        for(i=0; i<received_length; ++i) {
            if (i==6 || i==12 || 
                i==ETH_HLEN || i==ETH_HLEN+6 ||
                i==ETH_HLEN+7 || i==ETH_HLEN+8 ||
                i==ETH_HLEN+8+16 || i==ETH_HLEN+8+32) fprintf(stdout, " ");
            fprintf(stdout, "%02x", buf[i]);
        }
        fprintf(stdout, "\n");
        fflush(stdout);
        
    }
}

uint32_t calculate_icmpv6_checksum(unsigned char *buf, int totallen) {
    DECALRE_srcip_dstip_srcmac_dstmac_FROM_buf;
    
    uint32_t new_checksum = 0;
    buf[ETH_HLEN+8+32 + 2] = 0;
    buf[ETH_HLEN+8+32 + 3] = 0;
    
    checksum(srcip   , 16,   &new_checksum, 0);
    checksum(dstip   , 16,   &new_checksum, 0);
    int len = totallen  - (ETH_HLEN+8+32);
    unsigned char lenbuf[4]; lenbuf[0]=0; lenbuf[1]=0; lenbuf[2]=len>>8; lenbuf[3]=len&0xFF;
    checksum(lenbuf,               4,   &new_checksum, 0); // len
    checksum("\x00\x00\x00\x3A",   4,   &new_checksum, 0); // next header type
    checksum(buf + ETH_HLEN+8+32,  len, &new_checksum, 1);
    
    return new_checksum;    
}

int verify_and_fix_icmpv6_checksum(unsigned char *buf, int totallen) {
    unsigned long old_checksum = buf[ETH_HLEN+8+32 + 2]*256 + buf[ETH_HLEN+8+32 + 3];
    
    uint32_t new_checksum = calculate_icmpv6_checksum(buf, totallen);
   
    buf[ETH_HLEN+8+32 + 2] = new_checksum>>8;
    buf[ETH_HLEN+8+32 + 3] = new_checksum&0xFF;
    
    return (new_checksum == old_checksum) ? 0 : -1;
}


/*****************************************************************************
 * open_packet_socket
 *      Opens the packet-level socket, for incoming traffic,
 *      and sets up the appropriate BSD PF.
 *
 * Inputs:
 *  Index of the interface we're opening it for.
 *
 * Outputs:
 *  none
 *
 * Return:
 *      int sock on success, otherwise -1
 * 
 * This function is copied from [npd6](code.google.com/p/npd6/)
 *
 */
int open_packet_socket(int ifIndex)
{
    int sock, err;
    struct sock_fprog fprog;
    struct sockaddr_ll lladdr;
    // leave only ICMPv6
    static const struct sock_filter filter[] =
    {
        /*BPF_STMT(BPF_LD|BPF_B|BPF_ABS,
            ETH_HLEN +
            sizeof(struct ip6_hdr) +
            offsetof(struct icmp6_hdr, icmp6_type)),*/
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,
            ETH_HLEN +
            offsetof(struct ip6_hdr, ip6_nxt)),
        //BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ICMPV6, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, 0),
        BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
    };
    
    fprog.filter = (struct sock_filter *)filter;
    fprog.len = sizeof filter / sizeof filter[0];
   
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6) );
    if (sock < 0)
    {
        perror("socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6)");
        return (-1);
    }

    // Bind the socket to the interface we're interested in
    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_family = AF_PACKET;
    lladdr.sll_protocol = htons(ETH_P_IPV6);
    lladdr.sll_ifindex = ifIndex;
    lladdr.sll_hatype = 0;
    lladdr.sll_pkttype = 0;
    lladdr.sll_halen = 0;
    err=bind(sock, (struct sockaddr *)&lladdr, sizeof(lladdr));
    if (err < 0)
    {
        perror("bind PF_PACKET");
        return (-1);
    }

    // Tie the BSD-PF filter to the socket
    err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
    if (err < 0)
    {
        perror("setsockopt SO_ATTACH_FILTER");
        return (-1);
    }

    return sock;
}


int read_number_from_proc(const char* ifname, const char* knob) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s/%s", procsysnetipv6conf, ifname, knob);
    FILE* f = fopen(path, "r");
    if(!f) return -1;
    int x = -1;
    fscanf(f, "%d", &x);
    fclose(f);
    return x;
}

int write_number_to_proc(const char* ifname, const char* knob, int value) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s/%s", procsysnetipv6conf, ifname, knob);
    FILE* f = fopen(path, "w");
    if(!f) return -1;
    if (debug_mode & D_INIT) fprintf(stderr, "+ echo %d > %s\n", value, path);
    fprintf(f, "%d\n", value);
    fclose(f);
    return 0;
}

/*****************************************************************************
 * Inputs:
 *  ifname is interface name
 *  allmulti_state: 1-> Set (or confirm) flag is enabled
 *  allmulti_state: 0-> Set flag to unset condition.
 *
 * Outputs:
 *  savemacaddresshere - save 6 bytes of MAC address here
 *
 * Return:
 *  The previous value of the ALLMULTI flag, prior to change, 0 or 1
 * 
 * Notes:
 *  Miserere mihi peccatori.
 * 
 *  This function is based on if_allmulti from [npd6](code.google.com/p/npd6/)
 */
int setup_interface(const char *ifname, unsigned int allmulti_state, unsigned char* savemacaddresshere)
{
    struct ifreq    ifr;
    int skfd;
    int current;
    
    skfd = socket(AF_INET6, SOCK_DGRAM, 0);
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    
    
    
    if (savemacaddresshere) {
        if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
        {
            perror("ioctl SIOCGIFHWADDR");
            exit(1);
        }
        memcpy(savemacaddresshere, &ifr.ifr_hwaddr.sa_data, 6);
    }
    
    // Get current flags, etc.
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCGIFFLAGS");
        exit(1);
    }

    current = ifr.ifr_flags;
    
    if (! (options & NOALLMULTI)) {
        if (debug_mode & D_INIT && (!!allmulti_state != !!(ifr.ifr_flags&IFF_ALLMULTI))) {
            fprintf(stderr, "+ ip link set %s allmulticast %s\n", ifname, allmulti_state?"on":"off");
        }
        
        if (allmulti_state)
        {
            ifr.ifr_flags |= IFF_ALLMULTI;
            if (ifr.ifr_flags == current)
            {
                // Already set
                goto sinfulexit;;
            }
        }
        else
        {
            ifr.ifr_flags &= ~IFF_ALLMULTI;
        }
    
        if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("ioctl SIOCSIFFLAGS (+IFF_ALLMULTI)");
            exit(1);
        }
    }

sinfulexit:
    close(skfd);
    //fprintf(stderr, "%s %d\n", ifname, current);
    return !!(current & IFF_ALLMULTI);
}
