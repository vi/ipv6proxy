#!/bin/bash
set -e

P=ipv6proxy
V=0.1
FILES=".gitignore LICENSE Makefile README.md ipv6proxy.c maybe_add_route.sh maybe_del_route.sh popen_arr.c popen_arr.h scripts.h util.c util.h "

rm -Rf "$P"-$V
trap "rm -fR \"$P\"-$V" EXIT 
mkdir "$P"-$V
for i in $FILES; do cp -Rv ../"$i" "$P"-$V/; done
tar -czf ${P}_$V.orig.tar.gz "$P"-$V

cp -R debian "$P"-$V
(cd "$P"-$V && debuild)
