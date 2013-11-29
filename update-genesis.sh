#!/bin/bash

if [[ $# -ne 3 ]]
then
	echo "Usage: ./setup-instances.sh <directory> <count> <time offset>" >&2
	exit 1
fi

for i in $(seq 1 $2)
do
	sed -i "s/^time = .*$/time = $((($(date +%s)+$3)))/" $1/$i/dename.cfg
done
