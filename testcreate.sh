#!/bin/bash
echo "Create:"
for i in $(seq 1 $2)
do
    $1 -u 1 -k a create > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
