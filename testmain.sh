#!/bin/bash
mkdir -p results
trials=1

for i in `seq 2 14`
do
    echo "logleaves "$i

    runs=$(echo '2^'"$i" | bc)

    echo "Doing "$trials"x"$runs" operations"
    for j in $(seq 1 $trials)
    do

        ./testall.sh $i $runs 2> results/run_"$i"_"$j".txt
        sleep .2

        # dummy
        #./testdummy.sh $i $runs 2> results/dummy_"$i"_"$j".txt
        #sleep .2
    done
done
