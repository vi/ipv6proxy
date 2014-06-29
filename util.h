#pragma once


int my_if_nametoindex(int sock_fd, const char* devname);

void printhex(const unsigned char* buf, int n, FILE* f);
void printipv6(const unsigned char* ipv6, FILE* f);

int setup_interface(const char *ifname, unsigned int allmulti_state, unsigned char *savemacaddrhere);

int open_packet_socket(int ifIndex);

void maybe_add_route(const unsigned char *srcip, const char *ifname);
void maybe_del_route(const unsigned char *srcip, const char *ifname);


// currently unused:
// Add direct (without gateway) route to this address
int add_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex);
int del_ipv6_route(int sock_fd, struct in6_addr *addr,  int prefix_len, int metric, int ifindex);

void debug_print(const char* debug_print_mode, unsigned const char *buf, int received_length, const char* current_interface_name);


// Fix and/or verify IPCMv6 checksum; IPv6 packet is expected to be encapsupated in simple Ethernet frame
// -1 is fail, 0 is OK
int verify_and_fix_icmpv6_checksum(unsigned char *buf, int totallen);
