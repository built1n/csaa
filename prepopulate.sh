#!/bin/bash
# create databases and module states under databases/, each with
# 2^logleaves - runs_test files created and updated with one
# unencrypted version

mkdir -p databases

runs_test=500

# minimum is ceil(lg(runs_test)), otherwise modify will fail
for i in `seq 16 24`
do
    echo "logleaves "$i

    runs_create=$(echo '2^'"$i - $runs_test" | bc)

    echo "Doing "$runs_create" operations for create/modify"

    ./server $i databases/csaa_$i.db --overwrite > /dev/null &
    pid=$!

    sleep .2

    for j in `seq 1 $runs_create`
    do
        ./client -u 1 -k a create > /dev/null
        if [[ $? -ne 0 ]]
        then
            echo "Request failed!"
        fi

        ./client -u 1 -k a -f $j modifyfile -i container1/hello-world.tar > /dev/null

        if [[ $? -ne 0 ]]
        then
            echo "Request failed!"
        fi
    done

    kill -SIGINT $pid

    mv module_state databases/state_$i
done
