#!/bin/bash
./client -u 1 -k a create > /dev/null
for i in $(seq 1 1000)
do
    ./client -u 1 -k a modifyfile -f 1 -i container1/hello-world.tar > /dev/null
done
