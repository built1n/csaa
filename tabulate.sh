#!/bin/bash
trials=2
runs_test=500

rm -f all_*.txt dummy_all_*.txt

for i in `seq 9 15`
do
    for j in `seq 1 $trials`
    do
        echo -n "$i $j " >> all_"$i".txt
	echo -n "$i $j " >> dummy_all_"$i".txt
        cat run_"$i"_"$j".txt | awk '/Elapsed/ || /Maximum/ || /User time/ || /System time/' | awk 'BEGIN{line=0}{if(line%4<=1)printf($4" ");if(line %4==2)printf($8" ");if(line%4==3)printf($6" ");}{line+=1}END{printf("\n");}' >> all_"$i".txt
	
        cat dummy_"$i"_"$j".txt | awk '/Elapsed/ || /Maximum/ || /User time/ || /System time/' | awk 'BEGIN{line=0}{if(line%4<=1)printf($4" ");if(line %4==2)printf($8" ");if(line%4==3)printf($6" ");}{line+=1}END{printf("\n");}' >> dummy_all_"$i".txt
    done
done

rm -f data_create.txt data_modify.txt data_retrieve.txt data_modifyenc.txt data_retrieveenc.txt
rm -f data_dummy_create.txt data_dummy_modify.txt data_dummy_retrieve.txt

cat all_*.txt | awk '{
runs_create=lshift(1, $1);
runs_test='$runs_test';
if(NF >= 5)
 print $1, $5, runs_create >> "data_create.txt";
if(NF >= 9)
 print $1, $9, runs_test >> "data_modify.txt"
if(NF >= 13)
 print $1, $13, runs_test >> "data_retrieve.txt"
if(NF >= 17)
 print $1, $17, runs_test >> "data_modifyenc.txt"
if(NF >= 21)
 print $1, $21, runs_test >> "data_retrieveenc.txt"
}'

cat dummy_all_*.txt | awk '{
runs_create=lshift(1, $1);
runs_test='$runs_test';
if(NF >= 5)
 print $1, $5, runs_create >> "data_dummy_create.txt";
if(NF >= 9)
 print $1, $9, runs_test >> "data_dummy_modify.txt";
if(NF >= 13)
 print $1, $13, runs_test >> "data_dummy_retrieve.txt";
}'

for f in data*.txt
do
    echo $f
    cat $f | awk '{cmd = "echo " $2 " | ../timetosec.sh"; cmd | getline sec; print $1, sec, $3;}' > sec_$f
    cat sec_$f | ../postprocess | sort -n > final_$f
done
