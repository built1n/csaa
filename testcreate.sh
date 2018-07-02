#!/bin/bash
echo "Create:"
for i in $(seq 1 100)
do
    $1 -u 1 -k a create > /dev/null
done
