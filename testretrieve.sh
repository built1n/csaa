#!/bin/bash
echo "Retrieve:"
for i in $(seq 1 100)
do
    $1 -u 1 -k a retrievefile -f 1 -o out > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
