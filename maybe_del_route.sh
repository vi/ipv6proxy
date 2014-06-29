#!/bin/sh

IP="$1"
IF="$2"

if [ "$IP" == "0000:0000:0000:0000:0000:0000:0000:0000" ]; then
    exit 0;
fi

set -x
ip -6 route del $IP/128 dev $IF metric 5
