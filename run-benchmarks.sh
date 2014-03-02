#! /bin/bash

if [ ! -f client_sk ]; then
	echo "Client sk missing; please run as target user: keygen 2> client_sk >client_pk"
	exit 1
fi

targetuser=$1
if [[ -z "$targetuser" ]]; then
	echo "$0 \$USER"
	exit 1
fi

n=10000
for P in 1 2 4 8; do
	for k in 2 4 8 16 32 64; do
		dir="bench_k${k}P${P}"
		mkdir "$dir"
		./setup-instances.sh "$dir" "$k"
		./update-genesis.sh "$dir" "$k" 0
		chown -R "$targetuser" "$dir"
		cd "$dir"

		# start the servers...
		servers=()
		for i in $(seq 1 ${k}); do
			cd "$i"
			sudo -u "$targetuser" -- env "GOMAXPROCS=$P" ../../dename > stdout.log 2>stderr.log &
			servers+=($!)
			cd ..
		done

		sleep "$k"

		echo "../benchmarkthis.sh $n # $k servers, parallelism $P" 
		sudo -u "$targetuser" -- ../benchmarkthis.sh "$n"

		# stop the servers...
		for pid in "${servers[@]}"; do
			sudo -u "$targetuser" -- pkill -INT -P "$pid"
		done

		sleep 1
		sudo -u "$targetuser" pkill dename
		sleep 1

		cd ..
		chown -R "$targetuser" "$dir"
		./cleanup-instances.sh "$dir" "$k"
	done
done
