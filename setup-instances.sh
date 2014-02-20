#!/bin/bash

if [[ $# -ne 2 ]]
then
	echo "Usage: ./setup-instances.sh <directory> <count>" >&2
	exit 1
fi

dir="$1"
count="$2"
tmp_peer_config="$(mktemp)"

if [ ! -d "$dir" ]; then
	echo "\"$dir\" does not exist" >&2
	exit 1
fi

setup_instance() {
	mkdir -p "$dir/$1"
	sed -e "s/\$1/$1/g" dename.cfg > $dir/$1/dename.cfg
	host=$(grep -Pzo '\[general\]\n(.+\n)*host\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbname=$(grep -Pzo '\[database\]\n(.+\n)*name\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbuser=$(grep -Pzo '\[database\]\n(.+\n)*user\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbpw=$(grep -Pzo '\[database\]\n(.+\n)*password\s*=\s*\K.+' "$dir/$1/dename.cfg")
	pk=$(go run $GOPATH/src/github.com/andres-erbsen/sgp/keygen/keygen.go 2>"$dir/$1/sk" | tee "$dir/$1/pk" | base64 | tr -d '\n')
	echo "
[peer \"$1\"]
host = $host
publickey = $pk
" >> "$tmp_peer_config"
	echo "
CREATE USER \"$dbuser\" WITH PASSWORD '$dbpw';
CREATE DATABASE \"$dbname\";
GRANT ALL PRIVILEGES ON DATABASE \"$dbname\" to \"$dbuser\";
\\q" | sudo su - postgres -c psql
	sudo ip addr add local "$host/32" dev "lo:$1" scope host
}
	
for i in $(seq 1 "$count"); do setup_instance "$i"; done
for i in $(seq 1 "$count"); do cat "$tmp_peer_config" >> "$dir/$i/dename.cfg"; done
cp "$tmp_peer_config" "$dir/dnmlookup.cfg"

