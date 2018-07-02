#!/bin/bash
echo "Modify:"
$1 -u 1 -k a create > /dev/null
for i in $(seq 1 100)
do
    $1 -u 1 -k a modifyfile -f 1 -i container1/hello-world.tar > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
