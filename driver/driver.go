package driver

import (
	"database/sql"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/lib/pq"
)

var db *sql.DB

func ConnectDB() *sql.DB {
	// Connect to database
	error := godotenv.Load()
	if error != nil {
		log.Fatalf("Error loading .env file: %v", error)
	}
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))

	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	_ = err

	return db
}
