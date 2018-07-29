#!/bin/bash
if [[ $# -ne 3 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS_CREATE RUNS_TEST"
   exit 1
fi

runs_create=$2
runs_test=$3

echo "Initializing..."
rm files -rf

./server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2
./testcreate.sh ./client $runs_create
./testmodify.sh ./client $runs_test 1
./testretrieve.sh ./client $runs_test 1
./testmodifyenc.sh ./client $runs_test 1

echo "Encrypted retrieve: "
./testretrieve.sh ./client $runs_test 1
kill -SIGINT $!
rm csaa.db
