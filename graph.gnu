#!/usr/bin/gnuplot
set xlabel "logleaves"
set ylabel "avg time per operation (μs)"
set yrange [0:]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt -1 ps 0
set style line 3 pt -1 ps 0
set terminal eps

set output "graph_create.eps"

plot for[i=1:4] 'results/final_data_0_'.i.'.txt' u 1:2:3 title 'Create subtime '.i w yerrorbars, \
     for[i=1:4]	'results/final_data_0_'.i.'.txt' u 1:2 w lines ls i;

set output "graph_modify.eps"

plot for[i=1:1] 'results/final_data_1_'.i.'.txt' u 1:2:3 title 'Modify subtime '.i w yerrorbars ls 1, \
     for[i=1:1] 		'results/final_data_1_'.i.'.txt' u 1:2 w lines ls i;

set output "graph_retrieve.eps"

plot for[i=1:5] 'results/final_data_2_'.i.'.txt' u 1:2:3 title 'Retrieve subtime '.i w yerrorbars ls 1, \
for[i=1:5]     		'results/final_data_2_'.i.'.txt' u 1:2 w lines ls i;

set output "graph_modifyenc.eps"

plot for[i=1:1] 'results/final_data_3_'.i.'.txt' u 1:2:3 title 'Modify (encrypted) subtime '.i w yerrorbars ls 1, \
for[i=1:1]     		'results/final_data_3_'.i.'.txt' u 1:2 w lines ls i;

set output "graph_retrieveenc.eps"

plot for[i=1:5] 'results/final_data_4_'.i.'.txt' u 1:2:3 title 'Retrieve (encrypted) subtime '.i w yerrorbars ls 1, \
for[i=1:5]     		'results/final_data_4_'.i.'.txt' u 1:2 w lines ls i;
