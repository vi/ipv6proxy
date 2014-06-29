all: ipv6proxy

ipv6proxy: ipv6proxy.c util.c popen_arr.c
	${CC} -Wall -ggdb ipv6proxy.c util.c popen_arr.c -o ipv6proxy
