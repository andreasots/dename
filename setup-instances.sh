#!/bin/bash

if [[ $# -ne 2 ]]
then
	echo "Usage: ./setup-instances.sh <directory> <count>" >&2
	exit 1
fi

keygen=$(which keygen)
if [[ -z "$keygen" ]]; then
	keygen=./keygen
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
	listenat=$(grep -Pzo '\[general\]\n(.+\n)*listenat\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbname=$(grep -Pzo '\[database\]\n(.+\n)*name\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbuser=$(grep -Pzo '\[database\]\n(.+\n)*user\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbpw=$(grep -Pzo '\[database\]\n(.+\n)*password\s*=\s*\K.+' "$dir/$1/dename.cfg")
	pk=$($keygen 2>"$dir/$1/sk" | tee "$dir/$1/pk" | base64 | tr -d '\n')
	echo "
[peer \"$1\"]
connectto = $listenat
publickey = $pk
" >> "$tmp_peer_config"
	echo "
CREATE USER \"$dbuser\" WITH PASSWORD '$dbpw';
DROP DATABASE \"$dbname\";
CREATE DATABASE \"$dbname\";
GRANT ALL PRIVILEGES ON DATABASE \"$dbname\" to \"$dbuser\";
\\q" | sudo su - postgres -c psql
}
	
for i in $(seq 1 "$count"); do setup_instance "$i"; done
for i in $(seq 1 "$count"); do
	cat "$tmp_peer_config" >> "$dir/$i/dename.cfg"
	sed -i "s/^starttime = .*$/starttime = $((($(date +%s)+1)))/" "$dir/$i/dename.cfg"
done
sed 's/connectto = 127.0.0.1:13/connectto = 127.0.0.1:14/' "$tmp_peer_config" > "$dir/dnmlookup.cfg"


# setup the tokenserver
echo "
CREATE USER \"tokenserver\" WITH PASSWORD 'tokenpw';
DROP DATABASE \"tokendb\";
CREATE DATABASE \"tokendb\";
GRANT ALL PRIVILEGES ON DATABASE \"tokendb\" to \"tokenserver\";
\\q" | sudo su - postgres -c psql
dd bs=32 count=1 if=/dev/urandom "of=$dir/tokenserver_mac_key" status=none
