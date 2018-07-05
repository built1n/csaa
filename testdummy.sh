#!/bin/bash
echo "Initializing..."
rm csaa.db
sqlite3 csaa.db < sqlinit.txt
./dummy_server 10 csaa.db > /dev/null &
pid=$!
sleep 1
/usr/bin/time -v ./testcreate.sh ./dummy_client
/usr/bin/time -v ./testmodify.sh ./dummy_client
/usr/bin/time -v ./testretrieve.sh ./dummy_client
kill -SIGINT $!
