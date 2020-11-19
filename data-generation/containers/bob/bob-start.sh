ip4=$(ifconfig | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | grep -v 127.0.0.1 | awk '{ print $2 }' | cut -f2 -d:)
tcpdump -i eth0 -nn -vv -S -X -s0 -w /pdata/$AGENT_NAME.${ip4//\./-}.U.cap &>/dev/null &
DUMP_PID="$!"

pwsh ./simulate-traffic.ps1

kill -15 $DUMP_PID
wait $DUMP_PID