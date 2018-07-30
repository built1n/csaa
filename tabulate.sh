#!/bin/bash
logleaves_start=10
logleaves_end=12
trials=2
runs_test=500

rm -f all_*.txt dummy_all_*.txt

for i in `seq $logleaves_start $logleaves_end`
do
    for j in `seq 1 $trials`
    do
	echo -n "$i $j " >> dummy_all_"$i".txt
	
        # 5 operations in each file
        for k in `seq 0 4`
        do
            start=$(expr $runs_test \* $k + 1)
            end=$(expr $runs_test \* \( $k + 1 \))

	    echo -n "$i " > rundata_"$i"_"$j"_"$k".txt
            cat run_"$i"_"$j".txt | sed -n $start,$end'p' | ../average.sh | awk '{printf($1" ");}' >> rundata_"$i"_"$j"_"$k".txt
        done
        echo >> all_"$i".txt

        cat dummy_"$i"_"$j".txt | awk '/Elapsed/ || /Maximum/ || /User time/ || /System time/' | awk 'BEGIN{line=0}{if(line%4<=1)printf($4" ");if(line %4==2)printf($8" ");if(line%4==3)printf($6" ");}{line+=1}END{printf("\n");}' >> dummy_all_"$i".txt
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
