//go:build integration

package postgres

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestIssuerFoundationRLSAndConstraints(t *testing.T) {
	db := newTestDatabase(t)
	mustMigrate(t, db)
	mustBootstrap(t, db)

	pool := db.pool(t, "hukid_issuance_runtime")

	issA := "11111111-1111-4111-8111-111111111111"
	issB := "22222222-2222-4222-8222-222222222222"
	cliA := "33333333-3333-4333-8333-333333333333"
	coordX := strings.Repeat("a", 43)
	coordY := strings.Repeat("b", 43)
	secretHash := sha256.Sum256([]byte("events-secret-0123456789abcdef"))

	// Create issuer, active key, integration client and grant inside Tenant A.
	err := WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(testContext, `INSERT INTO tenancy.issuers(issuer_id,tenant_id,slug,issuer_uri,display_name) VALUES ($1,$2,'unas','https://issuer.hukid.pe/unas','IncubaUNAS')`, issA, TestTenantA); err != nil {
			return err
		}
		if _, err := tx.Exec(testContext, `INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,x_coord,y_coord) VALUES ($1,$2,'key-1','kms://unas/k1',$3,$4)`, TestTenantA, issA, coordX, coordY); err != nil {
			return err
		}
		if _, err := tx.Exec(testContext, `INSERT INTO tenancy.integration_clients(client_id,tenant_id,client_name,secret_hash,scopes) VALUES ($1,$2,'Events',$3,ARRAY['issuance:create','issuance:read'])`, cliA, TestTenantA, secretHash[:]); err != nil {
			return err
		}
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.integration_client_grants(tenant_id,client_id,issuer_id) VALUES ($1,$2,$3)`, TestTenantA, cliA, issA)
		return err
	})
	if err != nil {
		t.Fatalf("tenant A seed failed: %v", err)
	}
	assertCleared(t, pool)

	// Create issuer inside Tenant B.
	err = WithTenant(testContext, pool, TestActorB, TestTenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.issuers(issuer_id,tenant_id,slug,issuer_uri,display_name) VALUES ($1,$2,'other','https://issuer.hukid.pe/other','Other Org')`, issB, TestTenantB)
		return err
	})
	if err != nil {
		t.Fatalf("tenant B seed failed: %v", err)
	}

	// RLS prevents Tenant B from seeing Tenant A's issuers, keys, clients or grants.
	err = WithTenant(testContext, pool, TestActorB, TestTenantB, func(tx pgx.Tx) error {
		var issuersCount, keysCount, clientsCount, grantsCount int
		if err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.issuers`).Scan(&issuersCount); err != nil {
			return err
		}
		if err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.issuer_keys`).Scan(&keysCount); err != nil {
			return err
		}
		if err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.integration_clients`).Scan(&clientsCount); err != nil {
			return err
		}
		if err := tx.QueryRow(testContext, `SELECT count(*) FROM tenancy.integration_client_grants`).Scan(&grantsCount); err != nil {
			return err
		}
		if issuersCount != 1 || keysCount != 0 || clientsCount != 0 || grantsCount != 0 {
			t.Fatalf("RLS leak into tenant B: issuers=%d keys=%d clients=%d grants=%d", issuersCount, keysCount, clientsCount, grantsCount)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// RLS blocks Tenant A from inserting a row tagged with Tenant B.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.issuers(issuer_id,tenant_id,slug,issuer_uri,display_name) VALUES ('44444444-4444-4444-8444-444444444444',$1,'evil','https://issuer.hukid.pe/evil','Evil')`, TestTenantB)
		return err
	})
	expectCode(t, err, "42501")

	// Partial unique index rejects a second active key while key-1 is still active.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,x_coord,y_coord) VALUES ($1,$2,'key-2','kms://unas/k2',$3,$4)`, TestTenantA, issA, coordX, coordY)
		return err
	})
	expectCode(t, err, "23505")

	// Retiring key-1 and inserting active key-2 in one transaction succeeds.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(testContext, `UPDATE tenancy.issuer_keys SET state='retired',retired_at=now() WHERE tenant_id=$1 AND issuer_id=$2 AND kid='key-1'`, TestTenantA, issA); err != nil {
			return err
		}
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.issuer_keys(tenant_id,issuer_id,kid,kms_key_ref,x_coord,y_coord) VALUES ($1,$2,'key-2','kms://unas/k2',$3,$4)`, TestTenantA, issA, coordX, coordY)
		return err
	})
	if err != nil {
		t.Fatalf("key rotation transaction failed: %v", err)
	}

	// Cross-tenant FK rejects granting Tenant A's client access to Tenant B's issuer.
	err = WithTenant(testContext, pool, TestActorA, TestTenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(testContext, `INSERT INTO tenancy.integration_client_grants(tenant_id,client_id,issuer_id) VALUES ($1,$2,$3)`, TestTenantA, cliA, issB)
		return err
	})
	expectCode(t, err, "23503")
}
