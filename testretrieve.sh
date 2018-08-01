#!/bin/bash
# retrieve files $3-($3+$2), outputting to `out'
echo "Retrieve:"

stop=$(echo "$3+$2-1" | bc)

for i in $(seq $3 $stop)
do
    $1 -u 1 -k a retrievefile -f $i -o out -p > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
