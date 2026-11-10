// stagingdb provisions the remote "staging" database (ADR-0028): schema migrations, the
// runtime logins and the first administrator. It is a command-line helper only, never an
// HTTP endpoint, and refuses any target other than hukid_staging. It must run where the
// database host resolves (the Dokploy network), since the database publishes no port.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"hukid.local/platform/internal/adapters/postgres"
)

func main() {
	usage := "usage: stagingdb migrate | stagingdb runtime-logins | stagingdb bootstrap <issuer> <subject> <tenant name>\n" +
		"env: HUKID_ENV=staging, HUKID_DATABASE_URL (hukid_staging, explicit sslmode); runtime-logins also reads HUKID_RUNTIME_PASSWORD_<ROLE> for session, context, tenant, members, dashboard"
	args := os.Args[1:]
	valid := len(args) == 1 && (args[0] == "migrate" || args[0] == "runtime-logins") || len(args) == 4 && args[0] == "bootstrap"
	if !valid {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := postgres.ConnectStagingDatabase(ctx, os.Getenv("HUKID_DATABASE_URL"))
	if err == nil {
		defer conn.Close(context.Background())
		switch args[0] {
		case "migrate":
			err = postgres.Migrate(ctx, conn)
		case "runtime-logins":
			passwords := map[string]string{}
			for _, role := range postgres.RuntimeLoginRoles {
				passwords[role] = os.Getenv("HUKID_RUNTIME_PASSWORD_" + upper(role))
			}
			err = postgres.ProvisionRuntimeLogins(ctx, conn, passwords)
		default:
			err = postgres.BootstrapStaging(ctx, conn, args[1], args[2], args[3])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "staging database operation failed; check HUKID_ENV, target, privileges and schema (connection details omitted)")
		os.Exit(1)
	}
	fmt.Println("staging database operation completed")
}

func upper(value string) string {
	out := []byte(value)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 32
		}
	}
	return string(out)
}
