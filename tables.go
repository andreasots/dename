package main

import (
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
		id bigserial not null primary key,
		end_time bigint not null,
		commit_time bigint,
		signed_root bytea,
		naming_snapshot bigint);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// round_keys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS round_keys (
		id bigserial not null primary key,
		round bigint not null,
		server integer not null,
		key bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(server) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table round_keys: ", err)
	}

	// round_signatures
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS round_signatures (
		id bigserial not null primary key,
		round bigint not null,
		server integer not null,
		signature bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(server) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table round_signatures: ", err)
	}

	// names_we_transfer
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS names_we_transfer (
		id bigserial not null primary key,
		round bigint not null,
		name bytea not null,
		FOREIGN KEY(round) REFERENCES rounds(id));`)
	if err != nil {
		log.Fatal("Cannot create table names_we_transfer: ", err)
	}

	// transaction_queue
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transaction_queue (
		id bigserial not null primary key,
		round bigint not null,
		introducer integer not null,
		request bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(introducer) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table transaction_queue: ", err)
	}

	// commitments
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS commitments (
		id bigserial not null primary key,
		round bigint not null,
		commiter integer not null,
		acknowledger integer not null,
		signature bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(commiter) REFERENCES servers(id),
		FOREIGN KEY(acknowledger) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}

	// name_mapping
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS name_mapping (
		id bigserial not null primary key,
		name bytea not null,
		pubkey bytea not null,
		last_modified bigint not null,
		FOREIGN KEY(last_modified) REFERENCES rounds(id));`)
	if err != nil {
		log.Fatal("Cannot create table name_mapping: ", err)
	}
}
