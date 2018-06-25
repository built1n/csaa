#!/bin/bash
for i in $(seq 1 1000)
do
    ./client -u 1 -k a create > /dev/null
done
