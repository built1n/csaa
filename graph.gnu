set xlabel "logleaves"
set ylabel "avg time per operation (sec)"
set yrange [0:]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps .1
set terminal eps

set output "graph_create.eps"

plot "results/final_data_create.txt" u 1:2:3 w yerrorbars ls 1 title "1 SE", '' u 1:2 w lines ls 1 title "Create";

set output "graph_modify.eps"

plot "results/final_data_modify.txt" u 1:2:3 w yerrorbars ls 1 title "1 SE", '' u 1:2 w lines ls 1 title "Modify";

set output "graph_retrieve.eps"

plot "results/final_data_retrieve.txt" u 1:2:3 w yerrorbars ls 1 title "1 SE", '' u 1:2 w lines ls 1 title "Retrieve";

set output "graph_modifyenc.eps"

plot "results/final_data_modifyenc.txt" u 1:2:3 w yerrorbars ls 1 title "1 SE", '' u 1:2 w lines ls 1 title "Modify (encrypted)";

set output "graph_retrieveenc.eps"

plot "results/final_data_retrieveenc.txt" u 1:2:3 w yerrorbars ls 1 title "1 SE", '' u 1:2 w lines ls 1 title "Retrieve (encrypted)";
