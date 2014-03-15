#!/bin/bash

if [[ $# -ne 2 ]]
then
	echo "Usage: ./cleanup-instances.sh <directory> <count>" >&2
	exit 1
fi

dir="$1"
count="$2"

cleanup_instance() {
	rm -rf "$dir/$1"
	host=$(grep -Pzo '\[general\]\n(.+\n)*host\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbname=$(grep -Pzo '\[database\]\n(.+\n)*name\s*=\s*\K.+' "$dir/$1/dename.cfg")
	dbuser=$(grep -Pzo '\[database\]\n(.+\n)*user\s*=\s*\K.+' "$dir/$1/dename.cfg")
	echo "
DROP DATABASE \"$dbname\";
DROP USER \"$dbuser\";
\\q" | sudo su - postgres -c psql
}

for i in $(seq 1 "$count"); do cleanup_instance "$i"; done
