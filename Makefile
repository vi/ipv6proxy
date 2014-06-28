all: ipv6proxy

ipv6proxy: ipv6proxy.c icmp6.c popen_arr.c
	${CC} -Wall -ggdb ipv6proxy.c icmp6.c popen_arr.c -o ipv6proxy
