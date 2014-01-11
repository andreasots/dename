package consensus

import "log"

func (c *Consensus) createTables() {
	db := c.db
	// servers
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS servers (
		id serial not null primary key);`)
	if err != nil {
		log.Fatal("Cannot create table servers: ", err)
	}

	// rounds
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rounds (
		id bigserial not null primary key,
		our_key bytea not null,
		close_time bigint not null,
		signed_result bytea);`)
	if err != nil {
		log.Fatal("Cannot create table rounds: ", err)
	}

	// messages
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id bigserial not null primary key,
		round bigint not null,
		type integer not null,
		from integer not null,
		message bytea unique not null,
		FOREIGN KEY(round) REFERENCES rounds(id),
		FOREIGN KEY(from) REFERENCES servers(id));`)
	if err != nil {
		log.Fatal("Cannot create table commitments: ", err)
	}
}
