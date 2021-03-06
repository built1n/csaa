#!/bin/bash
if [[ $# -ne 3 ]]
then
    echo "Usage: "$0" START END TRIALS"
    exit 1
fi

logleaves_start=$1
logleaves_end=$2
trials=$3

runs_test=500

mkdir -p results

# minimum is ceil(lg(runs_test)), otherwise modify will fail
for j in $(seq 1 $trials)
do
    for i in `seq $logleaves_start $logleaves_end`
    do
        echo "logleaves "$i

        runs_create=$(echo '2^'"$i" | bc)

        echo "Doing "$trials"x"$runs_test" operations, with prepopulated database"
        ./testall_preinit.sh $i $runs_test 2> results/run_"$i"_"$j".txt
        sleep .2

        # dummy
        ./testdummy_preinit.sh $i $runs_test 2> results/dummy_"$i"_"$j".txt
        sleep .2
    done
done
