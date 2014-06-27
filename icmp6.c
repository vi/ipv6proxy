/*
 *   This software is Copyright 2011 by Sean Groarke <sgroarke@gmail.com>
 *   All rights reserved.
 *
 *   This file is part of npd6.
 *
 *   npd6 is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   npd6 is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with npd6.  If not, see <http://www.gnu.org/licenses/>.
 */

/* $Id: icmp6.c 160 2013-01-03 09:23:17Z sgroarke $
 * $HeadURL: https://npd6.googlecode.com/svn/trunk/icmp6.c $
 */

#include "includes.h"
#include <netpacket/packet.h>


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


/*****************************************************************************
 * open_icmpv6_socket
 *      Opens the ipv6-level socket, for outgoing traffic.
 *
 * Inputs:
 *  maxHops
 *
 * Outputs:
 *  none
 *
 * Return:
 *      int sock on success, otherwise -1
 *
 */
int open_icmpv6_socket(int maxHops)
{
    int sock, err;

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0)
    {
        perror("socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");
        return (-1);
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &maxHops, sizeof(maxHops));
    if (err < 0)
    {
        perror("setsockopt IPV6_UNICAST_HOPS");
        return (-1);
    }

    return sock;
}



/*****************************************************************************
 * get_rx
 *      Called from the dispatcher to pull in the received packet.
 *
 * Inputs:
 *  socket file descriptor
 *  buffer size
 *      
 * Outputs:
 *  unsigned char *msg
 *      The data.
 *
 * Return:
 *      int length of data received, otherwise -1 on error
 *
 * NOTES:
 * There's a lot of temp data structures needed here, but we really don't
 * care about them afterwards. Once we've got the raw data and the len
 * we're good.
 */

int get_rx(int sockpkt, unsigned char *msg, int maxsize) 
{
    struct sockaddr_in6 saddr;
    struct msghdr mhdr;
    struct iovec iov;
    int len;

reroll:
    iov.iov_len = maxsize;
    iov.iov_base = (caddr_t) msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)&saddr;
    mhdr.msg_namelen = sizeof(saddr);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;

    len = recvmsg(sockpkt, &mhdr, 0);

    /* Impossible.. But let's not take chances */
    if (len > maxsize)
    {
        fprintf(stderr, "Too many bytes received\n");
        return -1;
    }
    
    if (len < 0)
    {
        if (errno == EINTR || errno == EAGAIN) goto reroll;
        perror("recvmsg");
        return -1;
    }

    return len;
}



/*****************************************************************************
 * if_allmulti
 *      Called during startup and shutdown. Set/clear allmulti
 *      as required.
 *
 * Inputs:
 *  ifname is interface name
 *  state: 1-> Set (or confirm) flag is enabled
 *  state: 0-> Set flag to unset condition.
 *
 * Outputs:
 *  savemacaddresshere - save 6 bytes of MAC address here
 *
 * Return:
 *  The previous value of the flag, prior to change.
 * 
 * Notes:
 *  Miserere mihi peccatori.
 */
int if_allmulti(const char *ifname, unsigned int state, unsigned char* savemacaddresshere)
{
    struct ifreq    ifr;
    int skfd;
    int current;
    
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    // Get current flags, etc.
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCGIFFLAGS");
        exit(1);
    }
    
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl SIOCGIFHWADDR");
        exit(1);
    }

    current = ifr.ifr_flags;
    if (savemacaddresshere) {
        memcpy(savemacaddresshere, &ifr.ifr_hwaddr.sa_data, 6);
    }
    
    if (state)
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

sinfulexit:
    close(skfd);
    return (current || IFF_ALLMULTI);
}


/*****************************************************************************
 * init_sockets
 *  Initialises the tx and rx sockets. Normally just called during startup,
 *  but also to reinitialise sockets if they go bad.
 *
 * Inputs:
 *  void
 *
 * Outputs:
 *  Set global sockicmp and per i/f rx pkt socket
 *
 * Return:
 *  Non-0 if failure, else 0.
 */
/*
int init_sockets(void)
{
    int errcount = 0;
    int loop, sock, sockicmp;

    // Raw socket for receiving NSs
    for (loop=0; loop < interfaceCount; loop++)
    {
        sock = open_packet_socket(interfaces[loop].index);
  
        if (sock < 0)
        {
            flog(LOG_ERR, "open_packet_socket: failed on iteration %d", loop);
            errcount++;
        }
        interfaces[loop].pktSock = sock;
        flog(LOG_DEBUG, "open_packet_socket: %d OK.", loop);
        flog(LOG_DEBUG2, "open_packet_socket value = %d", sock);
    
        // ICMPv6 socket for sending NAs 
        sockicmp = open_icmpv6_socket();
        if (sockicmp < 0)
        {
            flog(LOG_ERR, "open_icmpv6_socket: failed.");
            errcount++;
        }
        flog(LOG_DEBUG, "open_icmpv6_socket: OK.");
        interfaces[loop].icmpSock = sockicmp;
    }
    
    return errcount;
}
*/
