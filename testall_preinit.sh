#!/bin/bash
if [[ $# -ne 2 ]]
then
   echo "Usage: "$0" LOGLEAVES RUNS_TEST"
   exit 1
fi

logleaves=$1
runs_test=$2

echo "Initializing..."
rm files -rf

cp databases/csaa_$logleaves.db csaa.db
cp databases/state_$logleaves module_state
chmod 644 csaa.db

start_id=$(echo "2^$1 - $runs_test" | bc)

./server $1 csaa.db > /dev/null &
pid=$!
sleep .2
/usr/bin/time -v ./testcreate.sh ./client $runs_test
/usr/bin/time -v ./testmodify.sh ./client $runs_test $start_id
/usr/bin/time -v ./testretrieve.sh ./client $runs_test $start_id
/usr/bin/time -v ./testmodifyenc.sh ./client $runs_test $start_id

echo "Encrypted retrieve: "
/usr/bin/time -v ./testretrieve.sh ./client $runs_test $start_id

kill -SIGINT $!
rm csaa.db module_state
