#!/bin/bash

dir=$1
count=$2

run_instance() {

	cd $dir/$1
	config=$(cat dename.cfg)

	re='\[database\].*^name = ([-a-zA-Z0-9$]+)'
	[[ $config =~ $re ]]
	dbname=${BASH_REMATCH[1]}

	re='\[database\].*^username = ([-a-zA-Z0-9$]+)'
	[[ $config =~ $re ]]
	dbuser=${BASH_REMATCH[1]}

	sudo su - postgres -c "dropdb $dbname"
	sudo su - postgres -c "createdb $dbname -O $dbuser"

	dename
}


./update-genesis.sh $1 $2 10
for i in $(seq 1 $count)
do
	run_instance $i&
done
