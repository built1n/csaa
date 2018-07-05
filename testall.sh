#!/bin/bash
if [[ $# -ne 1 ]]
then
   echo "Usage: "$0" LOGLEAVES"
   exit 1
fi
echo "Initializing..."
./server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep 1
/usr/bin/time -v ./testcreate.sh ./client
/usr/bin/time -v ./testmodify.sh ./client
/usr/bin/time -v ./testretrieve.sh ./client
/usr/bin/time -v ./testmodifyenc.sh ./client

echo "Encrypted retrieve: "
/usr/bin/time -v ./testretrieve.sh ./client
kill -SIGINT $!
