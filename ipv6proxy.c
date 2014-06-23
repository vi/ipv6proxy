#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include <stdio.h>
#include <string.h>



int main(int argc, char* argv[]) {
    int fd = socket( AF_INET6, SOCK_DGRAM, 0 );

    struct in6_rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    
    int prefix_len = 128;
    
    rt.rtmsg_dst_len = prefix_len;
	rt.rtmsg_flags = ((prefix_len == 128) ? (RTF_UP|RTF_HOST) : RTF_UP);
	rt.rtmsg_metric = 1;
	
	rt.rtmsg_ifindex = 0;
	
	const char *devname = "wifi0";
	
	if (devname) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		rt.rtmsg_ifindex = ifr.ifr_ifindex;
	}
	
	memcpy(&rt.rtmsg_dst, "\xFD\x00\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x66\x66\x66\x66", sizeof(struct in6_addr));

	ioctl(fd, SIOCADDRT, &rt);

    return 0;
}
