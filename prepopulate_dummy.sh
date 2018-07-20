#!/bin/sh

mkdir -p databases

pids=""

for i in `seq 10 25`
do
    echo $i
    rm -f socket
    ./dummy_server $i databases/dummy_$i.db > /dev/null &
    pids=$pids" "$!
done

wait $pids
