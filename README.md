ipv6proxy - IPv6 network NDP proxy router; `/64` network extender

Rationale
---
Imagine you have `/64` IPv6 network based on auto-configuration.
You can extend it using switches and bridges, but putting a router that splits `/64` further, interfering with address auto-configuration.

But making a bridge can be disrupting. Also bridging Wi-Fi in Linux can be problematic.

This program sets up a tricky router mode, like a "bridgeless bridge", proxying NDP and other ICMPv6 things and ensuring only one source MAC address is in use.

Usage
---

Imagine you have working `eth0` with auto-configured IPv6. You want to extend it to `wlan0`.

    IPV6PROXY_DEBUG=ism ./ipv6proxy eth0 wlan0 

This command with start ipv6proxy in default mode (it will set up `forwarding` and `accept_ra` values if necessary).
Upon terminationg ipv6proxy tries to revert everything back.

IPV6PROXY_DEBUG is only for making it to print more messages.

What the program does
---
It listens for ICMPv6 on all specified interfaces and each ICMPv6 packet it does see to all other interfaces, changing source and destination MAC addresses as necessary.
Additionally, special `/128` routes get added as necessary.

Non-ICMPv6 traffic gets forwarded by Linux as usual.

Supposing you have already working auto-configured setup at `eth0` and one remote node waiting to be configured at `wlan0`, ipv6proxy should print something like this, if started by command line above:


```
+ echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra
    (Force eth0 to stay auto-configured even though becoming a router)
+ echo 1 > /proc/sys/net/ipv6/conf/eth0/forwarding
    (Turn on forwarding)
+ ip link set eth0 allmulticast on
    (Turn on allmulticast mode)
+ echo 1 > /proc/sys/net/ipv6/conf/wlan0/forwarding
+ ip link set wlan0 allmulticast on
    (if accept_ra is 0, it is not changed by ipv6proxy)
FE8000000000000000C50AFFFEC19433:02C50AC19433 -> FF020000000000000000000000000001:333300000001 eth0(RouAdv)
Adding entry: FE8000000000000000C50AFFFEC19433 at eth0 mac 02C50AC19433
    (ipv6proxy saw a router advertisment on eth0 and forwarded it to wlan0)
    (   ,from the appropriate MAC address instead of 02C50AC19433)
00000000000000000000000000000000:FEC9D280DFA5 -> FF0200000000000000000001FF80DFA5:3333FF80DFA5 wlan0(NeigSol)
Adding entry: 00000000000000000000000000000000 at wlan0 mac FEC9D280DFA5
    (the node at wlan0 is booting up IPv6, checking for address duplicates)
FE8000000000000000C50AFFFEC19433:02C50AC19433 -> FF0200000000000000000001FF80DFA5:3333FF80DFA5 eth0(NeigSol)
FE8000000000000000C50AFFFEC19433:02C50AC19433 -> FF0200000000000000000001FF80DFA5:3333FF80DFA5 eth0(NeigSol)
200104707BD6E106FCC9D2FFFE80DFA5:FEC9D280DFA5 -> FE8000000000000000C50AFFFEC19433:5ACACAD9D63D wlan0(NeighAdv)
Adding entry: 200104707BD6E106FCC9D2FFFE80DFA5 at wlan0 mac FEC9D280DFA5
+ ip -6 route add 2001:0470:7bd6:e106:fcc9:d2ff:fe80:dfa5/128 dev veth_cm metric 5
    (the node have chosen the address, and we have added a route for it)
    (The node should have now IPv6 connectivity and be reachable from outside)
```

Prototype of the program: [setup_ipv6_hacky_router.sh](https://gist.github.com/vi/9633572)

Hacks
---
The project is eary and hacky. There are following known problems:

* Ping replies get duplicated;
* Source MAC address substitution code is hacky. Some special source MAC addresses may fail (it does search&replace MAC mentions though the whole packet and fix up ICMPv6 checksum afterwards).
* Usage of shell and /bin/ip to manage routes instead of AF_NETLINK;
* Not scalable approach in general - by design.
