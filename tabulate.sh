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

rm -f all_*.txt dummy_all_*.txt

for i in `seq $logleaves_start $logleaves_end`
do
    for j in `seq 1 $trials`
    do
        # 5 operations in each file
        for k in `seq 0 4`
        do
            start=$(expr $runs_test \* $k + 1)
	    if [[ $k -eq 0 ]]
	    then
		start=2 # discard first line (with preinserted placeholder)
	    fi
            end=$(expr $runs_test \* \( $k + 1 \))

	    echo -n "$i " > rundata_"$i"_"$j"_"$k".txt
            cat run_"$i"_"$j".txt | sed -n $start,$end'p' | ../average.sh | awk '{printf($1" ");}' >> rundata_"$i"_"$j"_"$k".txt
        done

	# only 3 operations for dummy
        for k in `seq 0 2`
        do
            start=$(expr $runs_test \* $k + 1)
	    if [[ $k -eq 0 ]]
	    then
		start=2 # discard first line (with preinserted placeholder)
	    fi
            end=$(expr $runs_test \* \( $k + 1 \))

	    echo -n "$i " > dummy_rundata_"$i"_"$j"_"$k".txt
            cat dummy_"$i"_"$j".txt | sed -n $start,$end'p' | ../average.sh | awk '{printf($1" ");}' >> dummy_rundata_"$i"_"$j"_"$k".txt
        done
    done
done

# generate the data files
for k in `seq 0 4`
do
    rm -f "data_"$k"_"*.txt	    
    for i in `seq $logleaves_start $logleaves_end`
    do
	for j in `seq 1 $trials`
	do
	    cat rundata_"$i"_"$j"_"$k".txt | awk '{for(i=2;i<=NF;i++) { print $1, $i >> "data_"'$k'"_"i - 1".txt";} }'
	done
    done
done

for k in `seq 0 4`
do
    for f in data_$k*
    do
	cat $f | ../postprocess > final_$f
    done
done

# dummy
for k in `seq 0 2`
do
    rm -f "dummy_data_"$k"_"*.txt	    
    for i in `seq $logleaves_start $logleaves_end`
    do
	for j in `seq 1 $trials`
	do
	    cat dummy_rundata_"$i"_"$j"_"$k".txt | awk '{for(i=2;i<=NF;i++) { print $1, $i >> "dummy_data_"'$k'"_"i - 1".txt";} }'
	done
    done
done

for k in `seq 0 2`
do
    for f in "dummy_data_"$k*
    do
	cat $f | ../postprocess > final_$f
    done
done
