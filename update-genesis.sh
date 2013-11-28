#!/bin/bash
for i in $(seq 1 $2)
do
	sed -i "s/^time = .*$/time = $((($(date +%s)+$3)))/" $1/$i/dename.cfg
done
