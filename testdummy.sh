#!/bin/bash
./dummy_server 10 csaa.db --overwrite > /dev/null &
pid=$!
sleep 5
time ./testcreate.sh ./dummy_client
time ./testmodify.sh ./dummy_client
kill -SIGINT $!
