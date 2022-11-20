## Source
#https://superuser.com/questions/1307732/how-to-send-binary-data-in-netcat-to-an-already-established-connection

output_file=admin_server_results.dump

# Create temporary directory
tmpd=`mktemp -d`
tmpf="$tmpd"/fifo
mkfifo "$tmpf"
echo "Temp dir: $tmpf"  # just to know the path to the fifo, it may be useful later

ncat -x $output_file -l 1080 < "$tmpf" &
ncpid=$!  # PID may be useful later
echo "Netcat pid: $ncpid"

exec 3> "$tmpf"

# Responses from server
echo -ne "\x01\x00" >&3 # Authentication OK

# ## To end the connection
# kill $ncpid
# exec 3>&-
# rm -rf $tmpf
# # or
# find /tmp -iname "tmp.*" 2> /dev/null | xargs rm -rf