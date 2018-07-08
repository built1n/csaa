#!/bin/bash
# retrieve files 1 - $2, outputting to `out'
echo "Retrieve:"
for i in $(seq 1 $2)
do
    $1 -u 1 -k a retrievefile -f $i -o out > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
