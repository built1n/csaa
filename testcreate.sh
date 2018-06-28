#!/bin/bash
for i in $(seq 1 100)
do
    ./client -u 1 -k a create > /dev/null
done
