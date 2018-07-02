#!/bin/bash
if [[ $# -ne 1 ]]
then
   echo "Usage: "$0" LOGLEAVES"
   exit 1
fi
echo "Initializing..."
./server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep 5
time ./testcreate.sh ./client
time ./testmodify.sh ./client
time ./testretrieve.sh ./client
time ./testmodifyenc.sh ./client

echo "Encrypted retrieve: "
time ./testretrieve.sh ./client
kill -SIGINT $!
