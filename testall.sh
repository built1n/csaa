#!/bin/bash
./server $1 csaa.db --overwrite > /dev/null &
pid=$!
sleep 5
echo "Create:"
time ./testcreate.sh ./client

echo "Modify:"
time ./testmodify.sh ./client

echo "Retrieve:"
time ./testretrieve.sh ./client

echo "Modify (encrypted):"
time ./testmodifyenc.sh ./client

echo "Retrieve (encrypted):"
time ./testretrieve.sh ./client
kill -SIGINT $!
