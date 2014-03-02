#! /bin/bash
P=900
regtoken='BPuWwRzl/gp279rMP3qgoAHbMi0bICSxOFJ+fjspJvU='

date '+%s%N' > "bench.start"
env GOMAXPROCS=80 ../bench $1
date '+%s%N' > "bench.end"

cat bench.start bench.end
