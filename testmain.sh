#!/bin/bash
mkdir -p results

for i in `seq 1 1`
do
    ./testdummy.sh 2> results/dummy_$i.txt
    sleep 1
done

for i in `seq 8 62`
do
    echo "logleaves "$i
    for j in `seq 1 1`
    do
        ./testall.sh $i 2> results/run_"$i"_"$j".txt
        # give time to close
        sleep 1
    done
done
