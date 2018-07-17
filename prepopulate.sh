#!/bin/bash
# create databases and module states under databases/, each with
# 2^logleaves - runs_test files created and updated with one
# unencrypted version

mkdir -p databases

runs_test=500

# minimum is ceil(lg(runs_test)), otherwise modify will fail
for i in `seq 9 15`
do
    echo "logleaves "$i

    runs_create=$(echo '2^'"$i - $runs_test" | bc)

    echo "Doing "$runs_create" operations for create"

    
    done
done
