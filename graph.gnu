#!/usr/bin/gnuplot
set key below
set xlabel "logleaves"
set ylabel "avg time per operation (μs)"
set yrange [0:2000]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt -1 ps 0
set style line 3 pt -1 ps 0
set terminal eps size 6in,6in

create_times = 14
modify_times = 1
retrieve_times = 5

create_labels = "`cat labels_0_create.txt | tr "\n" " "`"
modify_labels = "`cat labels_1_modify.txt | tr "\n" " "`"
retrieve_labels = "`cat labels_2_retrieve.txt | tr "\n" " "`"

set output "graph_create.eps"

plot for[i=3 * create_times - 1:2:-3] '< paste results/final_data_0_*.txt' u 1:(sum [col=2:i] column(col)) title 'Create '.word(create_labels, (i+1) / 3) w filledcurves x1, \
     for[i=3 * create_times - 1:2:-3] '< paste results/final_data_0_*.txt' u 1:(sum [col=2:i] column(col)):i+1 title '+/- 1.96 SE' w yerrorbars ls 1;

set output "graph_modify.eps"

plot for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_1_*.txt' u 1:(sum [col=2:i] column(col)) title 'Modify '.word(modify_labels, (i+1) / 3) w filledcurves x1, \
     for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_1_*.txt' u 1:(sum [col=2:i] column(col)):i+1 title '+/- 1.96 SE' w yerrorbars ls 1;

set output "graph_retrieve.eps"

plot for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_2_*.txt' u 1:(sum [col=2:i] column(col)) title 'Retrieve '.word(retrieve_labels, (i+1) / 3) w filledcurves x1, \
     for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_2_*.txt' u 1:(sum [col=2:i] column(col)):i+1 title '+/- 1.96 SE' w yerrorbars ls 1;

set output "graph_modifyenc.eps"

plot for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_3_*.txt' u 1:(sum [col=2:i] column(col)) title 'Encrypted modify '.word(modify_labels, (i+1) / 3) w filledcurves x1, \
     for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_3_*.txt' u 1:(sum [col=2:i] column(col)):i+1 title '+/- 1.96 SE' w yerrorbars ls 1;

set output "graph_retrieveenc.eps"

plot for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_4_*.txt' u 1:(sum [col=2:i] column(col)) title 'Encrypted retrieve '.word(retrieve_labels, (i+1) / 3) w filledcurves x1, \
     for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_4_*.txt' u 1:(sum [col=2:i] column(col)):i+1 title '+/- 1.96 SE' w yerrorbars ls 1;
