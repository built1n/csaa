#!/bin/bash
mkdir -p results
trials=2
runs_test=500

# minimum is ceil(lg(runs_test)), otherwise modify will fail
for i in `seq 9 15`
do
    echo "logleaves "$i

    runs_create=$(echo '2^'"$i" | bc)

    echo "Doing "$trials"x"$runs_create" operations for create, "$runs_test" for others"
    for j in $(seq 1 $trials)
    do
        ./testall.sh $i $runs_create $runs_test 2> results/run_"$i"_"$j".txt
        sleep .2

        # dummy
        ./testdummy.sh $i $runs_create $runs_test 2> results/dummy_"$i"_"$j".txt
        sleep .2
    done
done
