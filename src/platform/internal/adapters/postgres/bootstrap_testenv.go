package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ConnectTestDatabase is intentionally not a production provisioning command.
func ConnectTestDatabase(ctx context.Context, dsn string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil || os.Getenv("HUKID_ENV") != "test" || os.Getenv("HUKID_TEST_DATABASE") != "1" || dsn == "" {
		return nil, errors.New("explicit test database configuration is required")
	}
	if !testTarget(config) {
		return nil, errors.New("test database must use a loopback IP and a hukid_test_ database")
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot connect to the test database")
	}
	return conn, nil
}

func testTarget(config *pgx.ConnConfig) bool {
	ip := net.ParseIP(config.Host)
	return ip != nil && ip.IsLoopback() && strings.HasPrefix(config.Database, "hukid_test_") && config.TLSConfig == nil && len(config.Fallbacks) == 0
}

// LocalDatabase is the single persistent single-machine database accepted by the
// "local" profile. It must be loopback, non-TLS and without connection fallbacks.
const LocalDatabase = "hukid_local"

func localTarget(config *pgx.ConnConfig) bool {
	ip := net.ParseIP(config.Host)
	return ip != nil && ip.IsLoopback() && config.Database == LocalDatabase && config.TLSConfig == nil && len(config.Fallbacks) == 0
}

// runtimeTarget picks the database rule from the explicit process environment.
func runtimeTarget(config *pgx.ConnConfig) bool {
	switch os.Getenv("HUKID_ENV") {
	case "local":
		return localTarget(config)
	case "staging":
		return stagingTarget(config)
	}
	return testTarget(config)
}

const (
	TestTenantA      = "10000000-0000-4000-8000-000000000001"
	TestTenantB      = "10000000-0000-4000-8000-000000000002"
	TestActorA       = "20000000-0000-4000-8000-000000000001"
	TestActorB       = "20000000-0000-4000-8000-000000000002"
	TestActorPending = "20000000-0000-4000-8000-000000000003"
	TestMemberA      = "30000000-0000-4000-8000-000000000001"
	TestMemberB      = "30000000-0000-4000-8000-000000000002"
)

// BootstrapTest inserts one atomic synthetic fixture. Existing completed fixtures
// are never reset, reactivated or re-granted by subsequent calls.
func BootstrapTest(ctx context.Context, conn *pgx.Conn) error {
	if os.Getenv("HUKID_ENV") != "test" || os.Getenv("HUKID_TEST_DATABASE") != "1" || !testTarget(conn.Config()) {
		return errors.New("bootstrap is restricted to an explicit loopback test database")
	}
	var superuser bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&superuser); err != nil || !superuser {
		return errors.New("test bootstrap requires the isolated cluster administrator, never a runtime login")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(6721587302)`); err != nil {
		return err
	}
	var completed int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM platform.audit_events WHERE event_id IN ('40000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000002') AND action='test.bootstrap.completed'`).Scan(&completed); err != nil {
		return err
	}
	if completed == 2 {
		return tx.Commit(ctx)
	}
	if completed != 0 {
		return errors.New("inconsistent test bootstrap marker")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tenancy.operator_identities(operator_identity_id,oidc_issuer,subject) VALUES ($1,'http://127.0.0.1:19090','operator-test-pending')`, TestActorPending); err != nil {
		return err
	}
	for index, fixture := range []struct{ tenant, actor, member, subject, name string }{
		{TestTenantA, TestActorA, TestMemberA, "operator-test-a", "Organización de prueba A"},
		{TestTenantB, TestActorB, TestMemberB, "operator-test-b", "Organización de prueba B"},
	} {
		if _, err = tx.Exec(ctx, `INSERT INTO tenancy.tenants(tenant_id,display_name) VALUES ($1,$2)`, fixture.tenant, fixture.name); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tenancy.operator_identities(operator_identity_id,oidc_issuer,subject) VALUES ($1,'http://127.0.0.1:19090',$2)`, fixture.actor, fixture.subject); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tenancy.memberships(membership_id,tenant_id,operator_identity_id) VALUES ($1,$2,$3)`, fixture.member, fixture.tenant, fixture.actor); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tenancy.membership_roles(tenant_id,membership_id,role) VALUES ($1,$2,'tenant_admin')`, fixture.tenant, fixture.member); err != nil {
			return err
		}
		event := []string{"40000000-0000-4000-8000-000000000001", "40000000-0000-4000-8000-000000000002"}[index]
		if _, err = tx.Exec(ctx, `INSERT INTO platform.audit_events(event_id,tenant_id,actor_operator_identity_id,target_id,action,outcome,correlation_id) VALUES ($1,$2,$3,$4,'test.bootstrap.completed','success',$1)`, event, fixture.tenant, fixture.actor, fixture.member); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO platform.outbox_events(event_id,tenant_id) VALUES ($1,$2)`, event, fixture.tenant); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
