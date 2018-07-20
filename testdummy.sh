#!/bin/bash
if [[ $# -ne 3 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS_CREATE RUNS_TEST"
   exit 1
fi

runs_create=$2
runs_test=$3

echo "Initializing dummy..."
rm files -rf

./dummy_server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2
/usr/bin/time -v ./testcreate.sh ./dummy_client $runs_create
/usr/bin/time -v ./testmodify.sh ./dummy_client $runs_test 1
/usr/bin/time -v ./testretrieve.sh ./dummy_client $runs_test 1
kill -SIGINT $!
rm csaa.db
