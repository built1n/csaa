#!/usr/bin/gnuplot
set key below
set xlabel "logleaves"
set ylabel "average CPU time per operation for last 500 operations (μs)"
set yrange [0:2000]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt -1 ps 0
#set style line 3 pt -1 ps 0

set terminal eps size 6.5in,2.5in font "LiberationSerif"

create_times = "`wc -l labels_0_create.txt`"
modify_times = "`wc -l labels_1_modify.txt`"
retrieve_times = "`wc -l labels_2_retrieve.txt`"

create_labels = "`cat labels_0_create.txt | tr "\n" " "`"
modify_labels = "`cat labels_1_modify.txt | tr "\n" " "`"
retrieve_labels = "`cat labels_2_retrieve.txt | tr "\n" " "`"

dummy_create_times = "`wc -l dummy_labels_0_create.txt`"
dummy_modify_times = "`wc -l dummy_labels_1_modify.txt`"
dummy_retrieve_times = "`wc -l dummy_labels_2_retrieve.txt`"

dummy_create_labels = "`cat dummy_labels_0_create.txt | tr "\n" " "`"
dummy_modify_labels = "`cat dummy_labels_1_modify.txt | tr "\n" " "`"
dummy_retrieve_labels = "`cat dummy_labels_2_retrieve.txt | tr "\n" " "`"



set output "graph_create.eps"
#set terminal qt 0

set multiplot layout 1, 2 title "Create Performance"

set title "Authenticated"

plot for[i=3 * create_times - 1:2:-3] '< paste results/final_data_0_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Create '.word(create_labels, (i+1) / 3) w yerrorlines ls (create_times - (i-2)/3);

set title "Dummy"

plot for[i=3 * dummy_create_times - 1:2:-3] '< paste results/final_dummy_data_0_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Dummy Create '.word(dummy_create_labels, (i+1) / 3) w yerrorlines ls (dummy_create_times - (i-2)/3);

unset multiplot



set output "graph_modify.eps"
#set terminal qt 1

set multiplot layout 1, 2 title "Modify Performance"

set title "Authenticated"

plot for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_1_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Modify '.word(modify_labels, (i+1) / 3) w yerrorlines ls (modify_times - (i-2)/3);

set title "Dummy"

plot for[i=3 * dummy_modify_times - 1:2:-3] '< paste results/final_dummy_data_1_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Dummy Modify '.word(dummy_modify_labels, (i+1) / 3) w yerrorlines ls (dummy_modify_times - (i-2)/3);

unset multiplot



set output "graph_retrieve.eps"
#set terminal qt 2

set multiplot layout 1, 2 title "Retrieve Performance"

set title "Authenticated"

plot for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_2_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Retrieve '.word(retrieve_labels, (i+1) / 3) w yerrorlines ls (retrieve_times - (i-2)/3);

set title "Dummy"

plot for[i=3 * dummy_retrieve_times - 1:2:-3] '< paste results/final_data_2_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Dummy Retrieve '.word(dummy_retrieve_labels, (i+1) / 3) w yerrorlines ls (dummy_retrieve_times - (i-2)/3);

unset multiplot

set terminal eps size 3in,2.5in font "LiberationSerif"

set output "graph_modifyenc.eps"
#set terminal qt 3

set title "Authenticated Encrypted Modify Performance"

plot for[i=3 * modify_times - 1:2:-3] '< paste results/final_data_3_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Modify '.word(modify_labels, (i+1) / 3) w yerrorlines ls (modify_times - (i-2)/3);

set output "graph_retrieveenc.eps"
#set terminal qt 4

set title "Authenticated Encrypted Retrieve Performance"

plot for[i=3 * retrieve_times - 1:2:-3] '< paste results/final_data_4_*.txt' u 1:(sum [col=0:(i-2)/3] column(3 * col + 2)):i+1 title 'Retrieve '.word(retrieve_labels, (i+1) / 3) w yerrorlines ls (retrieve_times - (i-2)/3);
