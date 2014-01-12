package main

import "log"

func (dn *Dename) CreateTables() {
	db := dn.db
	// name_mapping
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		name bytea not null primary key,
		pubkey bytea);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}

	// name_locked
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_locked (
		name bytea not null unique primary key,
		request bytea);`)
	if err != nil {
		log.Fatal("Cannot create table name_locked: ", err)
	}

	// naming_snapshots
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS naming_snapshots (
		round bigint not null unique primary key,
		snapshot bigint not null);`)
	if err != nil {
		log.Fatal("Cannot create table naming_snapshots: ", err)
	}
}
