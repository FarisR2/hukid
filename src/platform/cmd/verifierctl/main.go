// verifierctl provisions per-tenant verification (VER-T11): the verifier
// configuration, the custodied signing key and the retention purge. It is a
// command-line helper only, never an HTTP endpoint: the signing key is
// generated and sealed here with the master key and reaches the database only
// as an AEAD envelope (ADR-0034), and the commands need a privileged login that
// the runtime roles do not have.
//
//	verifierctl configure <tenant-id> <client-id> <response-uri>
//	verifierctl provision-key <tenant-id>
//	verifierctl purge <retention-days> <limit>
//
// Environment: HUKID_ENV (staging, local or test) selects the connection guard
// of the matching database helper; HUKID_DATABASE_URL is the privileged login.
// provision-key also reads HUKID_VERIFICATION_KEY (base64, 32 bytes) and
// HUKID_VERIFICATION_KEY_VERSION, the same master key the API uses to open it.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/secretbox"
)

const usage = "usage: verifierctl configure <tenant-id> <client-id> <response-uri> | provision-key <tenant-id> | purge <retention-days> <limit>\n" +
	"env: HUKID_ENV=staging|local|test, HUKID_DATABASE_URL (privileged login); provision-key also HUKID_VERIFICATION_KEY and HUKID_VERIFICATION_KEY_VERSION"

var errUsage = errors.New(usage)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := validate(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conn, err := connect(ctx, os.Getenv("HUKID_ENV"), os.Getenv("HUKID_DATABASE_URL"))
	if err == nil {
		defer conn.Close(context.Background())
		err = run(ctx, conn, os.Getenv, os.Args[1:], os.Stdout, rand.Reader)
	}
	if err != nil {
		// Details stay out of the output: connection strings, key material and
		// database errors can all appear in them.
		fmt.Fprintln(os.Stderr, "verification provisioning failed; check HUKID_ENV, the target, the privileges, the arguments and the master key (details omitted)")
		os.Exit(1)
	}
}

func connect(ctx context.Context, environment, dsn string) (*pgx.Conn, error) {
	switch environment {
	case "staging":
		return postgres.ConnectStagingDatabase(ctx, dsn)
	case "local":
		return postgres.ConnectLocalDatabase(ctx, dsn)
	case "test":
		return postgres.ConnectTestDatabase(ctx, dsn)
	}
	return nil, errors.New("HUKID_ENV must be staging, local or test")
}

// validate checks the shape of the arguments before anything connects.
func validate(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	want := map[string]int{"configure": 4, "provision-key": 2, "purge": 3}[args[0]]
	if want == 0 || len(args) != want {
		return errUsage
	}
	return nil
}

func run(ctx context.Context, q postgres.Querier, env func(string) string, args []string, out io.Writer, random io.Reader) error {
	if err := validate(args); err != nil {
		return err
	}
	switch args[0] {
	case "configure":
		if err := postgres.ConfigureVerifier(ctx, q, args[1], args[2], args[3]); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "verifier configuration saved for tenant %s\n", args[1])
		return err
	case "provision-key":
		return provisionKey(ctx, q, env, args[1], out, random)
	default:
		days, errDays := strconv.Atoi(args[1])
		limit, errLimit := strconv.Atoi(args[2])
		if errDays != nil || errLimit != nil {
			return errUsage
		}
		sessions, keys, err := postgres.PurgeVerification(ctx, q, days, limit)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "purged %d sessions and %d retired keys\n", sessions, keys)
		return err
	}
}

// provisionKey generates a P-256 key, seals it with the master key and makes it
// the tenant's active key, retiring the previous one. It prints the kid and the
// public JWK, never the private key.
func provisionKey(ctx context.Context, q postgres.Querier, env func(string) string, tenant string, out io.Writer, random io.Reader) error {
	version := env("HUKID_VERIFICATION_KEY_VERSION")
	master, err := base64.StdEncoding.Strict().DecodeString(env("HUKID_VERIFICATION_KEY"))
	defer clear(master)
	if err != nil || len(master) != 32 || version == "" || len(version) > 128 {
		return errors.New("a 32-byte base64 master key and its version are required")
	}
	box, err := secretbox.New(master, version, random)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return err
	}
	kid, err := (&postgres.VerifierKeyProvisioner{Pool: q, Cipher: box}).Provision(ctx, tenant, key, nil)
	if err != nil {
		return err
	}
	public, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signing key installed for tenant %s\nkid %s\npublic %s\n", tenant, kid, public)
	return err
}
