#!/bin/bash

if [[ $# -ne 2 ]]
then
	echo "Usage: ./setup-instances.sh <directory> <count>" >&2
	exit 1
fi


dir=$1
count=$2

tmp_peer_config=`mktemp`

setup_instance() {
	mkdir $dir/$1
	config=$(cat dename.cfg | sed -e "s/\$2/$((($1+43)))/g" -e "s/\$1/$1/g")
	echo "$config" > $dir/$1/dename.cfg
	host=$(grep -Pzo '\[general\]\n(.+\n)*host\s*=\s*\K.+' $dir/$1/dename.cfg)
	dbname=$(grep -Pzo '\[database\]\n(.+\n)*name\s*=\s*\K.+' $dir/$1/dename.cfg)
	dbuser=$(grep -Pzo '\[database\]\n(.+\n)*user\s*=\s*\K.+' $dir/$1/dename.cfg)
	dbpassword=$(grep -Pzo '\[database\]\n(.+\n)*password\s*=\s*\K.+' $dir/$1/dename.cfg)
	sudo ip addr add $host/30 dev lo:$1
	cmd="
CREATE ROLE \"$dbuser\" WITH LOGIN PASSWORD '$dbpassword';
\\q" 
	echo $cmd | sudo su - postgres -c psql
	sudo su - postgres -c "dropdb $dbname"
	sudo su - postgres -c "createdb $dbname -O $dbuser"
	pk=$(go run $GOPATH/src/github.com/andres-erbsen/sgp/keygen/keygen.go 2>$dir/$1/sk | base64 | tr -d '\n')
	echo "
[peer \"$1\"]
host = $host
publickey = $pk
" >> $tmp_peer_config
}
mkdir $dir
for i in $(seq 1 $count)
do
	setup_instance $i
done
for i in $(seq 1 $count)
do
	cat $tmp_peer_config >> $dir/$i/dename.cfg
done

grep --after-context=999999 peer $dir/1/dename.cfg > $dir/dnmlookup.cfg
