#!/bin/bash
if [[ $# -ne 1 ]]
then
   echo "Usage: "$0" LOGLEAVES"
   exit 1
fi
echo "Initializing..."
./dummy_server 10 csaa.db --overwrite > /dev/null &
pid=$!
sleep 5
time ./testcreate.sh ./dummy_client
time ./testmodify.sh ./dummy_client
time ./testretrieve.sh ./dummy_client
kill -SIGINT $!
