#!/bin/bash

if [[ $# -ne 2 ]]
then
	echo "Usage: ./setup-instances.sh <directory> <count>" >&2
	exit 1
fi


dir=$1
count=$2

tmp_config=`mktemp`
cp dename.cfg $tmp_config

config=$(cat $tmp_config)

re='\[general\].*^host = ([0-9.i$]+)'
[[ $config =~ $re ]]
host_pattern=${BASH_REMATCH[1]}

re='\[database\].*^name = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbname_pattern=${BASH_REMATCH[1]}

re='\[database\].*^username = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbuser_pattern=${BASH_REMATCH[1]}

re='\[database\].*^password = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbpassword_pattern=${BASH_REMATCH[1]}

setup_instance() {
	mkdir $dir/$1
	host=$(echo $host_pattern | sed "s/\$1/$((($i+43)))/g")
	dbname=$(eval echo $dbname_pattern)
	dbuser=$(eval echo $dbuser_pattern)
	dbpassword=$(eval echo $dbuser_pattern)
	sudo ip addr add $host/30 dev lo:$1
	cmd="
CREATE ROLE \"$dbuser\" WITH LOGIN PASSWORD '$dbpassword';
\\q" 
	echo $cmd | sudo su - postgres -c psql
	sudo su - postgres -c "dropdb $dbname"
	sudo su - postgres -c "createdb $dbname -O $dbuser"
	pk=$(go run $GOPATH/src/github.com/andres-erbsen/sgp/keygen/keygen.go 2>$dir/$1/sk | base64 | tr -d '\n')
	echo "
[peer \"$pk\"]
host = $host" >> $tmp_config
}
mkdir $dir
for i in $(seq 1 $count)
do
	setup_instance $i
done
for i in $(seq 1 $count)
do
	host=$(echo $host_pattern | sed "s/\$1/$((($i+43)))/g")

	sed -e "s/$host_pattern/$host/g" -e "s/\$1/$i/g" $tmp_config > $dir/$i/dename.cfg
done
