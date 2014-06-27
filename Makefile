all: ipv6proxy

ipv6proxy: ipv6proxy.c icmp6.c
	${CC} -Wall -ggdb ipv6proxy.c icmp6.c -o ipv6proxy
