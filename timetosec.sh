#!/bin/bash
awk -F: '{ print ($1 * 60) + $2 }'
