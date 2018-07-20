#!/bin/sh

mkdir -p databases

pids=""
for i in `seq 10 12`
do
    echo $i
    rm -f socket
    ./server $i databases/csaa_$i.db > /dev/null &

    pids=$pids" "$!
done

wait $pids
