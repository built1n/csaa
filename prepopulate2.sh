#!/bin/sh

mkdir -p databases

for i in `seq 10 25`
do
    echo $i
    rm -f socket
    ./server $i databases/csaa_$i.db > /dev/null
done
