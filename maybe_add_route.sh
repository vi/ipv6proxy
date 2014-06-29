#!/bin/sh

IP="$1"
IF="$2"

if [ "$IP" = "0000:0000:0000:0000:0000:0000:0000:0000" ]; then
    exit 0;
fi

if ip -6 route get $IP | grep -Fq "dev $IF "; then
    : # route seems to be correct already
else
    set -x
    ip -6 route add $IP/128 dev $IF metric 5
fi
