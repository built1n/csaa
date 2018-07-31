#!/bin/bash
# modify files $3 - ($3 + $2), creating a new version with fixed contents
echo "Modify:"

stop=$(echo "$3+$2" | bc)

for i in $(seq $3 $stop)
do
    $1 -u 1 -k a modifyfile -f $i -i container1/hello-world.tar -p > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
