#!/bin/bash
awk -F: '{ if(NF==2)print(($1 * 60) + $2);else print(($1 * 3600) + ($2 * 60) + $3);}'
