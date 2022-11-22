IFS=$'\n'
list=$*

echo -ne "admin\nadmin\n$list\n" | bin/socks5c -L localhost -P 8080
