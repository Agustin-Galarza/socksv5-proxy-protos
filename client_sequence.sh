IFS=$'\n'
list=$*

echo -ne "admin\nadmin\n$list" | bin/socks5c -L localhost -P 8080
