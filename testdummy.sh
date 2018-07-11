#!/bin/bash
if [[ $# -ne 2 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS"
   exit 1
fi

runs=$2

echo "Initializing dummy..."
rm files -rf

./dummy_server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2
/usr/bin/time -v ./testcreate.sh ./dummy_client $runs
/usr/bin/time -v ./testmodify.sh ./dummy_client $runs
/usr/bin/time -v ./testretrieve.sh ./dummy_client $runs
kill -SIGINT $!
rm csaa.db
