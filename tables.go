package main

import (
	_ "github.com/mattn/go-sqlite3"
	"log"
)

func (dn *Dename) CreateTables() {
	db := dn.db
	// servers
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS servers (
		id serial not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table servers: ", err)
	}

	// rounds
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id serial not null primary key,
		end_time integer not null);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// round_keys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS round_keys (
		id serial not null primary key,
		round integer not null,
		server integer not null,
		key bytea not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(server) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table round_keys: ", err)
	}

	// transaction_queue
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transaction_queue (
		id serial not null primary key,
		round integer not null,
		introducer integer not null,
		request bytea not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(introducer) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table transaction_queue: ", err)
	}

	// commitments
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS commitments (
		id serial not null primary key,
		round integer not null,
		commiter integer not null,
		acknowledger integer not null,
		signature bytea not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(commiter) REFERENCES servers(id),
		FOREIGN KEY(acknowledger) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}

	// name_mapping
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		id serial not null primary key,
		name bytea not null,
		pubkey bytea not null);`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}
}
