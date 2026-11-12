// testdb is a local test migration/provisioning tool, never an HTTP endpoint.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"hukid.local/platform/internal/adapters/postgres"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "migrate" && os.Args[1] != "bootstrap" && os.Args[1] != "invalidate-auth") {
		fmt.Fprintln(os.Stderr, "usage: testdb migrate|bootstrap|invalidate-auth (isolated test databases only)")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := postgres.ConnectTestDatabase(ctx, os.Getenv("HUKID_DATABASE_URL"))
	if err == nil {
		defer conn.Close(context.Background())
		if os.Args[1] == "migrate" {
			err = postgres.Migrate(ctx, conn)
		} else if os.Args[1] == "bootstrap" {
			err = postgres.BootstrapTest(ctx, conn)
		} else {
			err = postgres.InvalidateAuthTest(ctx, conn)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "test database operation failed; check test flags, privileges and schema (connection details omitted)")
		os.Exit(1)
	}
	fmt.Println("test database operation completed")
}
