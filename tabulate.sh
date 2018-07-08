#!/bin/bash
for i in `seq 4 10`
do
    rm -f all_"$i".txt
    for j in `seq 1 3`
    do
        echo -n "$i $j " >> all_"$i".txt
        cat run_"$i"_"$j".txt | awk '/Elapsed/ || /Maximum/ || /User time/ || /System time/' | awk 'BEGIN{line=0}{if(line%4<=1)printf($4" ");if(line %4==2)printf($8" ");if(line%4==3)printf($6" ");}{line+=1}END{printf("\n");}' >> all_"$i".txt
    done
done

rm -f data_create.txt data_modify.txt data_retrieve.txt data_modifyenc.txt data_retrieveenc.txt
cat all_*.txt | awk '{print $1, $5 >> "data_create.txt";
 print $1, $9 >> "data_modify.txt"
 print $1, $13 >> "data_retrieve.txt"
 print $1, $17 >> "data_modifyenc.txt"
 print $1, $21 >> "data_retrieveenc.txt"
}'

for f in data*.txt
do
    echo $f
    cat $f | awk '{cmd = "echo " $2 " | ../timetosec.sh"; cmd | getline sec; print $1, sec}' > sec_$f
    cat sec_$f | ../postprocess | sort -n > final_$f
done
