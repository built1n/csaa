#!/bin/bash

echo "Initializing..."
rm files -rf

./server 10 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2

# the three operations should have the same labels no matter if
# they're encrypted or not
./client -u 1 -k a create # prime
./client -u 1 -k a create -p --labels-only 2> labels_0_create.txt
./client -u 1 -k a modifyfile -f 1 -i container1/hello-world.tar -p --labels-only 2> labels_1_modify.txt
./client -u 1 -k a retrievefile -f 1 -o out -p --labels-only 2> labels_2_retrieve.txt

kill -SIGINT $pid
rm csaa.db

# dummy
echo "Initializing..."
rm files -rf

./dummy_server 10 csaa.db --overwrite > /dev/null &
pid=$!
sleep .2

# the three operations should have the same labels no matter if
# they're encrypted or not
./dummy_client -u 1 -k a create -p --labels-only 2> dummy_labels_0_create.txt
./dummy_client -u 1 -k a modifyfile -f 1 -i container1/hello-world.tar -p --labels-only 2> dummy_labels_1_modify.txt
./dummy_client -u 1 -k a retrievefile -f 1 -o out -p --labels-only 2> dummy_labels_2_retrieve.txt

kill -SIGINT $pid
rm csaa.db
