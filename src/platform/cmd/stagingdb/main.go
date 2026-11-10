// stagingdb provisions the remote "staging" database (ADR-0028): schema migrations and
// the first administrator. It is a command-line helper only, never an HTTP endpoint, and
// refuses any target other than hukid_staging. It must run where the database host
// resolves (the Dokploy network), since the database publishes no port.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"hukid.local/platform/internal/adapters/postgres"
)

func main() {
	usage := "usage: stagingdb migrate | stagingdb bootstrap <issuer> <subject> <tenant name> (HUKID_ENV=staging, HUKID_DATABASE_URL to hukid_staging with an explicit sslmode)"
	args := os.Args[1:]
	if len(args) == 0 || (args[0] == "migrate" && len(args) != 1) || (args[0] == "bootstrap" && len(args) != 4) || (args[0] != "migrate" && args[0] != "bootstrap") {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := postgres.ConnectStagingDatabase(ctx, os.Getenv("HUKID_DATABASE_URL"))
	if err == nil {
		defer conn.Close(context.Background())
		if args[0] == "migrate" {
			err = postgres.Migrate(ctx, conn)
		} else {
			err = postgres.BootstrapStaging(ctx, conn, args[1], args[2], args[3])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "staging database operation failed; check HUKID_ENV, target, privileges and schema (connection details omitted)")
		os.Exit(1)
	}
	fmt.Println("staging database operation completed")
}
