all: ipv6proxy

ipv6proxy: ipv6proxy.c
	${CC} -Wall -ggdb ipv6proxy.c -o ipv6proxy
