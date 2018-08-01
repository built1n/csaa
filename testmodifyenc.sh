#!/bin/bash
echo "Modify (encrypted):"

stop=$(echo "$3+$2-1" | bc)

for i in $(seq $3 $stop)
do
    $1 -u 1 -k a modifyfile -e -f $i -i container1/hello-world.tar -p > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
