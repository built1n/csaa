#!/bin/bash
if [[ $# -ne 2 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS_TEST"
   exit 1
fi

logleaves=$1
runs_test=$2

echo "Initializing dummy..."
rm files -rf

cp databases/dummy_$logleaves.db csaa.db
chmod 644 csaa.db

./dummy_server $1 csaa.db > /dev/null &

start_id=$(echo "2^$1 - $runs_test + 1" | bc)

pid=$!
sleep .2
./testcreate.sh ./dummy_client $runs_test
./testmodify.sh ./dummy_client $runs_test $start_id
./testretrieve.sh ./dummy_client $runs_test $start_id

kill -SIGINT $!

rm csaa.db
