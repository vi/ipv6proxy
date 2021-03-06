
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
#include <signal.h>


#include <stdio.h>

#include "util.h"

#define ETH_HLEN  14


struct myinterface {
    const char* name;
    int ifindex;
    int flags;
    unsigned char macaddr[6];
    int packetsock_fd;
    int prevallmulti;
    int prevforward;
    int prevacceptra;
};


#define MAX_INTERFACES 128
#define MAX_IPMAP_SIZE 4096

struct myinterface interfaces[MAX_INTERFACES];
int n_interfaces;


struct ip_map_entry {
    unsigned char ip[16];
    unsigned char mac[6];
    int ifindex;
};


struct ip_map_entry ip_map[MAX_IPMAP_SIZE];
int n_ip_map = 0;


unsigned char buf[4096];

enum debugmode_t debug_mode = 0;

volatile int exit_flag = 0;

const char* procsysnetipv6conf = "/proc/sys/net/ipv6/conf";

static void signal_handler() {
    exit_flag = 1;
}

enum myflags_t options = 0;

int main(int argc, char* argv[]) {
    
    if(argc<2 || !strcmp(argv[1], "--help")) {
        fprintf(stderr, "Usage: ipv6proxy eth0 wlan0 ...\n");
        fprintf(stderr, "Environtment variables\n");
        fprintf(stderr, "    IPV6PROXY_DEBUG=[s][d][m][i] - output short debug info, packet dumps, ip_map operations and init log respectively\n");
        fprintf(stderr, "    IPV6PROXY_PROCROOT=/proc/sys/net/ipv6/conf/ - override /proc path\n");
        fprintf(stderr, "    IPV6PROXY_OPTIONS=[M][R][F][A][N]\n");
        fprintf(stderr, "        M - don't set allmulticast\n");
        fprintf(stderr, "        R - don't add or delete routes\n");
        fprintf(stderr, "        F - don't set up forwarding=1\n");
        fprintf(stderr, "        A - don't automatically set up accept_ra=2 instead of 1\n");
        fprintf(stderr, "        N - don't restore anything back on exit\n");
        return 1;
    }
    
    if(getenv("IPV6PROXY_DEBUG")) {
        const char* o = getenv("IPV6PROXY_DEBUG");
        if(strchr(o, 'd')) debug_mode |= D_PACKET_DUMPS;
        if(strchr(o, 's')) debug_mode |= D_SHORT;
        if(strchr(o, 'm')) debug_mode |= D_IP_MAP;
        if(strchr(o, 'i')) debug_mode |= D_INIT;
    }
    if(getenv("IPV6PROXY_PROCROOT")) procsysnetipv6conf=getenv("IPV6PROXY_PROCROOT");
    if(getenv("IPV6PROXY_OPTIONS")) {
        const char* o = getenv("IPV6PROXY_OPTIONS");
        if(strchr(o, 'M')) options |= NOALLMULTI;
        if(strchr(o, 'R')) options |= NOROUTES;
        if(strchr(o, 'F')) options |= NOFORWARDING;
        if(strchr(o, 'A')) options |= NOACCEPTRA;
        if(strchr(o, 'N')) options |= NORESTORE;
    }
    
    {
        struct sigaction sa = {{&signal_handler}};
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
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
        
        ii->prevforward = read_number_from_proc(devname, "forwarding");
        ii->prevacceptra = read_number_from_proc(devname, "accept_ra");
        
        if (ii->prevforward == -1 || ii->prevacceptra == -1) {
            fprintf(stderr, "Error getting interface parameters from /proc\n");
            return 1;
        }
        
        if (! (options & NOACCEPTRA) && ii->prevacceptra == 1) {
            if(write_number_to_proc(devname, "accept_ra", 2) == -1) {
                fprintf(stderr, "Failed to set up accept_ra on the interface\n");
                return 1;
            }
        }
        if (! (options & NOFORWARDING) && ii->prevforward == 0) {
            if(write_number_to_proc(devname, "forwarding", 1) == -1) {
                fprintf(stderr, "Failed to set up forwarding on the interface\n");
                return 1;
            }
        }
        
        ii->prevallmulti = setup_interface(devname, 1, ii->macaddr);
        
        ii->packetsock_fd = open_packet_socket(ifindex);
        if(ii->packetsock_fd < 0) return 1;
    }
        
    
    for(;!exit_flag;) {
        
        fd_set rfds;
        int maxfd = 0;
        FD_ZERO(&rfds);
        for (i=0; i<n_interfaces; ++i) {
            struct myinterface *current_interface = &interfaces[i];
            int fd = current_interface->packetsock_fd;
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
            struct myinterface *current_interface = &interfaces[i];
            int fd = current_interface->packetsock_fd;
            if (fd!=-1 && FD_ISSET(fd, &rfds)) {
                ret = recv(fd, buf, sizeof buf, 0);
                if(ret<0) {
                    if(errno==EINTR || errno==EAGAIN) continue;
                    perror("recv");
                    close(current_interface->packetsock_fd);
                    current_interface->packetsock_fd = -1;
                }
                
                int received_length = ret;
                if (received_length < ETH_HLEN+40+4) {
                    fprintf(stderr, "Short packet received...\n");
                    continue;
                }
                if (verify_and_fix_icmpv6_checksum(buf, received_length) == -1) {
                    fprintf(stderr, "ICMPv6 checksum fail\n");
                    continue;
                }
                
                unsigned char *srcip = buf + ETH_HLEN+8;
                unsigned char *dstip = buf + ETH_HLEN+8+16;
                unsigned char *dstmac = buf ;
                unsigned char *srcmac = buf + 6;
                
                unsigned char icmp_type = buf[ETH_HLEN+8+32]; (void)icmp_type;
                debug_print(debug_mode, buf, received_length, current_interface->name);
                
                
                int j;
                
                // tricky trick: find all mentions of the source MAC address to be overwritten
                const int maxmentions=10;
                int mac_mentions_indexes[maxmentions];
                int nummentions=0;
                
                int current_offset = 0;
                for(;nummentions<maxmentions && current_offset < received_length-5;){
                    unsigned char* q = (unsigned char*)
                                memmem(buf+current_offset, received_length-current_offset,
                                       buf+6, 6);
                    if(!q)break;
                    int offset = q-buf;
                    current_offset = offset+6;
                    
                    //fprintf(stderr, "Found mention %d in %d bytes packet af offset %d\n", nummentions, received_length, offset);
                    mac_mentions_indexes[nummentions++] = offset;
                }
                //fprintf(stderr, ".\n");
                
                for (j=0; j<n_ip_map; ++j) {
                    struct ip_map_entry *ipmap_entry = &ip_map[j];
                    if(!memcmp(ipmap_entry->ip, srcip, 16)) {
                        if (! !memcmp(ipmap_entry->mac, srcmac, 6)) {
                            if (debug_mode & D_IP_MAP) {
                                fprintf(stderr, "Updating mac for ");
                                    printhex(srcip, 16, stderr);
                                fprintf(stderr, " to ");
                                    printhex(srcmac, 6, stderr);
                                fprintf(stderr, "\n");
                            }
                            memcpy(ipmap_entry->mac, srcmac, 6);
                        }
                        
                        if (ipmap_entry->ifindex != i) {
                            maybe_del_route(srcip, interfaces[ipmap_entry->ifindex].name);
                            maybe_add_route(srcip, current_interface->name);
                            if (debug_mode & D_IP_MAP) {
                                fprintf(stderr, "Updating network interface for ");
                                    printhex(srcip, 16, stderr);
                                fprintf(stderr, " to %s\n", current_interface->name);
                            }
                            ipmap_entry->ifindex = i;
                        }
                        break;
                    }
                }
                if (j==n_ip_map) {
                    // not found
                    if (n_ip_map == MAX_IPMAP_SIZE) {
                        // evict random entry
                        j = rand() % MAX_IPMAP_SIZE;
                        struct ip_map_entry *evicted_ipmap_entry = &ip_map[j];
                        
                        if (debug_mode & D_IP_MAP) {
                            fprintf(stderr, "Evicting entry: ");
                                printipv6(evicted_ipmap_entry->ip, stderr);
                            fprintf(stderr, " at %s mac ", interfaces[evicted_ipmap_entry->ifindex].name);
                                printhex(evicted_ipmap_entry->mac, 6, stderr);
                            fprintf(stderr, "\n");
                        }
                        maybe_del_route(evicted_ipmap_entry->ip, interfaces[evicted_ipmap_entry->ifindex].name);
                    } else {
                        // add new entry
                        ++n_ip_map;
                    }
                    
                    struct ip_map_entry *new_ipmap_entry = &ip_map[j];
                    new_ipmap_entry->ifindex = i;
                    memcpy(new_ipmap_entry->mac, srcmac, 6);
                    memcpy(new_ipmap_entry->ip, srcip, 16);
                    
                    if (debug_mode & D_IP_MAP) {
                        fprintf(stderr, "Added entry to map: ");
                            printipv6(new_ipmap_entry->ip, stderr);
                        fprintf(stderr, " at %s mac ", current_interface->name);
                            printhex(new_ipmap_entry->mac, 6, stderr);
                        fprintf(stderr, "\n");
                    }
                    maybe_add_route(srcip, current_interface->name);
                }
                
                
                // If we know the MAC for this destination IP, use it
                for (j=0; j<n_ip_map; ++j) {
                    struct ip_map_entry *ipmap_entry = &ip_map[j];
                    if(!memcmp(ipmap_entry->ip, dstip, 16)) {
                        memcpy(dstmac, ipmap_entry->mac, 6);
                        break;
                    }
                }
                // if not, just preserver original destination MAC
                
                // Send the packet everywhere (except of originating interface), just to be sure. We are not scalable anyway.
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
                    
                    (void)verify_and_fix_icmpv6_checksum(buf, received_length);
                    
                    
                    again:
                    ret = send(interfaces[j].packetsock_fd, buf, received_length, 0);
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
    
    if (options & NORESTORE) return 0;
    // cleanup: remove routes we have added and restore ALLMULTI statuses
    
    // remove routes
    {
        int j;
        for (j=0; j<n_ip_map; ++j) {
            struct ip_map_entry *ipmap_entry = &ip_map[j];
            maybe_del_route(ipmap_entry->ip, interfaces[ipmap_entry->ifindex].name);
        }
    }
    
    // maybe reset ALLMULTIs
    for(i=0; i<n_interfaces; ++i){
        struct myinterface *ii = &interfaces[i];
        (void)setup_interface(ii->name, ii->prevallmulti, ii->macaddr);
        
        // maybe restore forwarding value
        if (! (options & NOFORWARDING) && ii->prevforward != 1) {
            write_number_to_proc(ii->name, "forwarding", ii->prevforward);
        }
        // maybe restore accept_ra value
        if (! (options & NOACCEPTRA) && ii->prevacceptra == 1) {
            write_number_to_proc(ii->name, "accept_ra", ii->prevacceptra);
        }
    }
    
    return 0;
}
