IFS=$'\n'
list=$*

echo -ne "admin\nadmin\n$list\n" | bin/socks5c -Y -L localhost -P 8080
