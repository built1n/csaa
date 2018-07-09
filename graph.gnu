set xlabel "logleaves"
set ylabel "avg time per operation (sec)"
set yrange [0:]

set terminal eps

set output "graph_create.eps"

plot "results/final_data_create.txt" u 1:2 w lines title "Create";

set output "graph_modify.eps"

plot "results/final_data_modify.txt" u 1:2 w lines title "Modify";

set output "graph_retrieve.eps"

plot "results/final_data_retrieve.txt" u 1:2 w lines title "Retrieve";

set output "graph_modifyenc.eps"

plot "results/final_data_modifyenc.txt" u 1:2 w lines title "Modify (enc)";

set output "graph_retrieveenc.eps"

plot "results/final_data_retrieveenc.txt" u 1:2 w lines title "Retrieve (enc)";
