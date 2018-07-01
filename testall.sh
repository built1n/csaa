#!/bin/bash
./server 10 csaa.db --overwrite > /dev/null &
pid=$!
sleep 5
time ./testcreate.sh ./client
time ./testmodify.sh ./client
kill -SIGINT $!
