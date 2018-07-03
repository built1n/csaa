#!/bin/bash
echo "Initializing..."
rm csaa.db
sqlite3 csaa.db < sqlinit.txt
./dummy_server 10 csaa.db > /dev/null &
pid=$!
sleep 1
time ./testcreate.sh ./dummy_client
time ./testmodify.sh ./dummy_client
time ./testretrieve.sh ./dummy_client
kill -SIGINT $!
