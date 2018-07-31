#!/bin/bash
mkdir -p results
trials=1
runs_test=500

# minimum is ceil(lg(runs_test)), otherwise modify will fail
for i in `seq 10 12`
do
    echo "logleaves "$i

    runs_create=$(echo '2^'"$i" | bc)

    echo "Doing "$trials"x"$runs_test" operations, with prepopulated database"
    for j in $(seq 1 $trials)
    do
        ./testall_preinit.sh $i $runs_test 2> results/run_"$i"_"$j".txt
        sleep .2

        # dummy
        ./testdummy_preinit.sh $i $runs_test 2> results/dummy_"$i"_"$j".txt
        sleep .2
    done
done
