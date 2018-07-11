#!/bin/bash
if [[ $# -ne 2 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS"
   exit 1
fi

runs=$2

echo "Initializing..."
rm files -rf

./server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2
/usr/bin/time -v ./testcreate.sh ./client $runs
/usr/bin/time -v ./testmodify.sh ./client $runs
/usr/bin/time -v ./testretrieve.sh ./client $runs
/usr/bin/time -v ./testmodifyenc.sh ./client $runs

echo "Encrypted retrieve: "
/usr/bin/time -v ./testretrieve.sh ./client $runs
kill -SIGINT $!
rm csaa.db
