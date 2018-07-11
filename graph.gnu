set xlabel "logleaves"
set ylabel "avg time per operation (sec)"
set yrange [0:]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt -1 ps 0
set style line 3 pt -1 ps 0
set terminal eps

set output "graph_create.eps"

plot "results/final_data_create.txt" u 1:2:3 w yerrorbars ls 1 title "+/- 1.96 SE", '' u 1:2 w lines ls 2 title "Create", \
     "results/final_data_dummy_create.txt" u 1:2:3 w yerrorbars ls 3 title "+/- 1.96 SE", '' u 1:2 w lines ls 4 title "Dummy Create";

set output "graph_modify.eps"

plot "results/final_data_modify.txt" u 1:2:3 w yerrorbars ls 1 title "+/- 1.96 SE", '' u 1:2 w lines ls 2 title "Modify", \
     "results/final_data_dummy_modify.txt" u 1:2:3 w yerrorbars ls 3 title "+/- 1.96 SE", '' u 1:2 w lines ls 4 title "Dummy Modify";

set output "graph_retrieve.eps"

plot "results/final_data_retrieve.txt" u 1:2:3 w yerrorbars ls 1 title "+/- 1.96 SE", '' u 1:2 w lines ls 2 title "Retrieve", \
     "results/final_data_dummy_retrieve.txt" u 1:2:3 w yerrorbars ls 3 title "+/- 1.96 SE", '' u 1:2 w lines ls 4 title "Dummy Retrieve";

set output "graph_modifyenc.eps"

plot "results/final_data_modifyenc.txt" u 1:2:3 w yerrorbars ls 1 title "+/- 1.96 SE", '' u 1:2 w lines ls 2 title "Modify (encrypted)";

set output "graph_retrieveenc.eps"

plot "results/final_data_retrieveenc.txt" u 1:2:3 w yerrorbars ls 1 title "+/- 1.96 SE", '' u 1:2 w lines ls 2 title "Retrieve (encrypted)";
