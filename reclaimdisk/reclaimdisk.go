package main

import (
	"database/sql"
	"fmt"
	"github.com/andres-erbsen/dename/consensus"
	"log"
	"os"
)

func diskUsage(db *sql.DB) (ret int64) {
	err := db.QueryRow(`SELECT pg_database_size(current_database());`).Scan(&ret)
	if err != nil {
		log.Fatalf("(c *Consensus) diskUsage(): %s", err)
	}
	return
}

func reclaimDiskSpace(db *sql.DB, beforeRound, downToBytes, threshold int64) {
	remaining := diskUsage(db) - downToBytes
	for remaining > threshold {
		// expect deleteable messages to be at most 5kb per round
		roundsToClean := remaining/5000 + 1
		rs, err := db.Exec(`DELETE FROM messages WHERE ctid = ANY(ARRAY(
			SELECT ctid FROM messages WHERE type != $1 AND round < $2
			ORDER BY id ASC LIMIT $3));`, consensus.PUSH, beforeRound, roundsToClean)
		if err != nil {
			log.Fatalf("(c *Consensus) diskUsage(): %s", err)
		}
		if n, _ := rs.RowsAffected(); n == 0 {
			break
		}
		_, err = db.Exec(`VACUUM ANALYZE messages;`)
		if err != nil {
			log.Fatalf("(c *Consensus) diskUsage(): %s", err)
		}
		remaining = diskUsage(db) - downToBytes
	}
}

func main() {
	if len(os.Args) != 6 {
		log.Fatalf("USAGE: %s DB USER PW ROUNDS BYTES", os.Args[0])
	}
	dbname, dbuser, dbpw := os.Args[1], os.Args[2], os.Args[3]
	var rounds, sizelimit int64
	if _, err := fmt.Sscanf(os.Args[4], "%d", &rounds); err != nil {
		log.Fatal(err)
	}
	if _, err := fmt.Sscanf(os.Args[5], "%d", &sizelimit); err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("postgres", "user="+dbuser+" password="+dbpw+" dbname="+dbname+" sslmode=disable")
	if err != nil {
		log.Fatalf("Open db: %s", err)
	}
	round := int64(0)
	err = db.QueryRow(`SELECT id FROM rounds ORDER BY id DESC LIMIT 1 OFFSET $1;`, rounds).Scan(&round)
	if err != nil {
		log.Fatalf("Select N rounds ago: %s", err)
	}
	log.Printf("Up to round %d", round)
	reclaimDiskSpace(db, round, sizelimit, 500000)
}
