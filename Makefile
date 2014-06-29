all: ipv6proxy

ipv6proxy: ipv6proxy.c util.c popen_arr.c scripts.c
	${CC} -Wall -ggdb ipv6proxy.c util.c popen_arr.c scripts.c -o ipv6proxy

scripts.c: maybe_add_route.sh maybe_del_route.sh
	echo "#include \"scripts.h\"" > scripts.c

	echo "const unsigned char script_maybe_add_route[] = {"    >> scripts.c
	( cat maybe_add_route.sh; printf '\x00'; ) | xxd -i  >> scripts.c
	echo "};"    >> scripts.c
	
	echo "const unsigned char script_maybe_del_route[] = {"    >> scripts.c
	( cat maybe_del_route.sh; printf '\x00'; ) | xxd -i  >> scripts.c
	echo "};"    >> scripts.c
