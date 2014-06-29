#pragma once

// Add direct (without gateway) route to this address
int add_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex);
int del_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex);




int my_if_nametoindex(int sock_fd, const char* devname);

void printhex(unsigned char* buf, int n, FILE* f);

void checksum (void * buffer, int bytes, uint32_t *total, int finalize);

// to be refactored
int if_allmulti(const char *ifname, unsigned int state, unsigned char *savemacaddrhere);

int open_packet_socket(int ifIndex);

void maybe_add_route(const unsigned char *srcip, const char *ifname);
