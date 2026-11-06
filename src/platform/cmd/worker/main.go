// Laboratory-only explicit tenant batch. No global scan or real email transport.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hukid.local/platform/internal/adapters/memberconfig"
	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/adapters/secretbox"
	"hukid.local/platform/internal/tenancy"
	"os"
	"time"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "invitation worker failed")
		os.Exit(1)
	}
}
func run() error {
	invalid := errors.New("isolated invitation worker configuration required")
	if len(os.Args) != 3 || os.Getenv("HUKID_ENV") != "test" {
		return invalid
	}
	actor, tenant := os.Args[1], os.Args[2]
	dsn, path := os.Getenv("HUKID_MEMBERS_DATABASE_URL"), os.Getenv("HUKID_MEMBERS_POLICY")
	if postgres.ValidateLoginDatabase(dsn) != nil {
		return invalid
	}
	secrets, err := memberconfig.Load()
	if err != nil || secrets == nil {
		return invalid
	}
	defer secrets.Clear()
	file, err := os.Open(path)
	if err != nil {
		return invalid
	}
	defer file.Close()
	policy, err := tenancy.LoadMembershipPolicy(file, "test")
	if err != nil {
		return invalid
	}
	box, err := secretbox.New(secrets.Key, secrets.Version, rand.Reader)
	if err != nil {
		return invalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := postgres.OpenRuntimePool(ctx, dsn, "hukid_members_runtime", 4)
	if err != nil {
		return invalid
	}
	defer pool.Close()
	store := &postgres.InvitationStore{Pool: pool, Now: time.Now, Policy: policy}
	worker := &tenancy.InvitationWorker{Store: store, Provider: &postgres.SyntheticNotifications{Store: store, Actor: actor}, Cipher: box, Now: time.Now}
	return worker.Run(ctx, actor, tenant)
}
