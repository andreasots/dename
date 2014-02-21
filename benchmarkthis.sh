#! /bin/bash
n=$1
P=$2
regtoken=ChieoCB38onSW4kBiUeuXDhIrePYJEJwSu0aACJACI7CjQrHmNOLC+LwsHUW5HOOxyaWcEGV0959bF0UISN7U26gSsuE83mxGq14VcnHy3vr6264Eyh+p4kz6nrYDw==

date '+%s%N' > "bench.start"
seq 1 ${n} | xargs -P${P} -n1 ../dnmreg/dnmreg ../client_sk "$regtoken"
date '+%s%N' > "bench.end"

cat bench.start bench.end
