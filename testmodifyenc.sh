#!/bin/bash
echo "Modify (encrypted):"
for i in $(seq 1 $2)
do
    $1 -u 1 -k a modifyfile -e -f $i -i container1/hello-world.tar > /dev/null
    if [[ $? -ne 0 ]]
    then
        echo "Request failed!"
    fi
done
