ip4=$(ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
tcpdump -i eth0 -nn -vv -S -X -s0 -w /pdata/$AGENT_NAME.${ip4//\./-}.M.cap &>/dev/null &
DUMP_PID="$!"


end=$(($(date +%s)+(60*DATA_GENERATIONS_MINUTES)))

while [ $(date +%s) -lt $end ]
do
    flightsim run scan
done


kill -15 $DUMP_PID
wait $DUMP_PID