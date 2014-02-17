package main

import "log"

func (dn *Dename) CreateTables() {
	db := dn.db
	// rainbow
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS rainbow (
		hash bytea not null primary key,
		preimage bytea not null);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}

	// naming_snapshots
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS naming_snapshots (
		round bigint not null unique primary key,
		snapshot bigint not null);`)
	if err != nil {
		log.Fatal("Cannot create table naming_snapshots: ", err)
	}

	// used_tokens
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS used_tokens (
		nonce bytea not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table used_tokens: ", err)
	}
}
