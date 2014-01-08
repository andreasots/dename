package main

import (
	"log"
)

func (dn *Dename) CreateTables() {
	db := dn.db
	// === general consensus === //
	// servers
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS servers (
		id serial not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table servers: ", err)
	}

	// rounds
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id bigserial not null primary key,
		snapshot_number bigint,
		snapshot_hash bytea);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// messages
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id bigserial not null primary key,
		round bigint not null,
		type integer not null,
		from integer not null,
		to integer not null,
		message bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(from) REFERENCES servers(id),
		FOREIGN KEY(to) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}

	// === naming === //
	// name_mapping
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		name bytea not null primary key,
		pubkey bytea not null;`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}

	// name_locked
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_locked (
		round bigint not null,
		name bytea not null,
		PRIMARY KEY(round, name),
		FOREIGN KEY(round) REFERENCES rounds(id));`)
	if err != nil {
		log.Fatal("Cannot create table name_locked: ", err)
	}

}
