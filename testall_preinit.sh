#!/bin/bash
if [[ $# -ne 2 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS_TEST"
   exit 1
fi

logleaves=$1
runs_test=$2

echo "Initializing..."
rm files csaa.db module_state -rf

cp databases/csaa_$logleaves.db csaa.db
cp databases/state_$logleaves module_state

chmod 644 csaa.db module_state

start_id=$(echo "2^$1 - $runs_test + 1" | bc)

./server $1 csaa.db > /dev/null &
pid=$!
sleep .2
./testcreate.sh ./client $runs_test
./testmodify.sh ./client $runs_test $start_id
./testretrieve.sh ./client $runs_test $start_id
./testmodifyenc.sh ./client $runs_test $start_id

echo "Encrypted retrieve: "
./testretrieve.sh ./client $runs_test $start_id

kill -SIGINT $!
rm csaa.db module_state
