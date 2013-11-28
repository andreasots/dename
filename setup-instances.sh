#!/bin/bash

dir=$1
count=$2

tmp_config=`mktemp`
cp dename.cfg $tmp_config

config=$(cat $tmp_config)

re='\[general\].*host = ([0-9.i$]+)'
[[ $config =~ $re ]]
host_pattern=${BASH_REMATCH[1]}

re='\[database\].*name = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbname_pattern=${BASH_REMATCH[1]}

re='\[database\].*username = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbuser_pattern=${BASH_REMATCH[1]}

re='\[database\].*password = ([-a-zA-Z0-9$]+)'
[[ $config =~ $re ]]
dbpassword=${BASH_REMATCH[1]}

setup_instance() {
	mkdir $dir/$1
	host=$(eval echo $host_pattern)
	dbname=$(eval echo $dbname_pattern)
	dbuser=$(eval echo $dbuser_pattern)
	sudo ip addr add $host/30 dev lo:$1
	cmd="
CREATE ROLE \"$dbuser\" WITH LOGIN PASSWORD '$dbpassword';
\\q" 
	echo $cmd | sudo -u postgres psql
	sudo -u postgres dropdb $dbname
	sudo -u postgres createdb $dbname -O $dbuser
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
	sed "s/\$1/$i/g" $tmp_config > $dir/$i/dename.cfg
done
