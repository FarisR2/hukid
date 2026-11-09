// localdb provisions the persistent single-machine "local" database. It is a
// command-line helper only, never an HTTP endpoint, and refuses non-local targets.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"hukid.local/platform/internal/adapters/postgres"
)

func main() {
	usage := "usage: localdb migrate | localdb bootstrap <issuer> <subject> <tenant name> (HUKID_ENV=local, hukid_local on loopback only)"
	args := os.Args[1:]
	if len(args) == 0 || (args[0] == "migrate" && len(args) != 1) || (args[0] == "bootstrap" && len(args) != 4) || (args[0] != "migrate" && args[0] != "bootstrap") {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := postgres.ConnectLocalDatabase(ctx, os.Getenv("HUKID_DATABASE_URL"))
	if err == nil {
		defer conn.Close(context.Background())
		if args[0] == "migrate" {
			err = postgres.Migrate(ctx, conn)
		} else {
			err = postgres.BootstrapLocal(ctx, conn, args[1], args[2], args[3])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "local database operation failed; check HUKID_ENV, target, privileges and schema (connection details omitted)")
		os.Exit(1)
	}
	fmt.Println("local database operation completed")
}
