#!/bin/bash
for i in `seq 10 62`; do for j in `seq 1 1`; do echo -n "$i $j "; cat run_"$i"_"$j".txt | awk '/Elapsed/ || /Maximum/ || /User time/ || /System time/' | awk 'BEGIN{line=0}{if(line%4<=1)printf($4" ");if(line %4==2)printf($8" ");if(line%4==3)printf($6" ");}{line+=1}END{printf("\n");}'; done; done
