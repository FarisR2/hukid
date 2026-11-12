package authentication

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type readStore struct {
	value    ReadSession
	err      error
	calls    int
	writes   int
	writeErr error
}

func (s *readStore) ReadSession(context.Context, []byte, time.Time) (ReadSession, error) {
	s.calls++
	return s.value, s.err
}
func (s *readStore) TouchSession(context.Context, []byte, time.Time, time.Duration) error {
	return s.err
}
func (s *readStore) ReconcileSessionContext(_ context.Context, _ []byte, _ ReadSession, next ContextSelection, _ time.Time) error {
	s.writes++
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.err != nil {
		return s.err
	}
	s.value.ActiveTenantID, s.value.AuthorizationRevision = next.TenantID, next.Revision
	return nil
}

type contextReader struct {
	value ContextSelection
	err   error
}

func (r contextReader) SessionContext(context.Context, string, string) (ContextSelection, error) {
	return r.value, r.err
}

func TestSessionContextRevalidationFailsClosedAndPreservesAuthentication(t *testing.T) {
	now := time.Unix(2000000000, 0)
	cookie := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, name := range []string{"unchanged", "revision", "suspended", "dependency", "write_failure", "missing_port"} {
		t.Run(name, func(t *testing.T) {
			store := &readStore{value: ReadSession{FamilyID: "family", ActorID: "actor", ActiveTenantID: "tenant", AuthorizationRevision: 1, PolicyVersion: "auth-test-v1", Generation: 1, CSRFHash: Digest(cookie), CreatedAt: now.Add(-time.Minute), FamilyCreatedAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour)}}
			plain, _ := encodeSecrets("access", "refresh", cookie)
			reader := contextReader{value: ContextSelection{TenantID: "tenant", Revision: 1}}
			s := SessionService{Store: store, Cipher: readCipher{data: plain}, Policy: Policy{SessionAbsoluteSeconds: 3600, SessionIdleSeconds: 1800}, Now: func() time.Time { return now }}
			switch name {
			case "revision", "write_failure":
				reader.value.Revision = 2
			case "suspended":
				reader.err = ErrTenant
			case "dependency":
				reader.err = ErrDependency
			}
			if name == "write_failure" {
				store.writeErr = ErrDependency
			}
			if name != "missing_port" {
				s.Contexts = reader
			}
			v, err := s.Read(context.Background(), cookie)
			wantError := name == "dependency" || name == "write_failure" || name == "missing_port"
			if wantError {
				if !errors.Is(err, ErrDependency) || v.AccessToken != "" {
					t.Fatal("failed open", err)
				}
				return
			}
			if err != nil || v.AccessToken != "access" || v.CSRF != cookie {
				t.Fatal("authentication lost", err)
			}
			if name == "suspended" && (v.ActiveTenantID != "" || store.value.AuthorizationRevision != 0) {
				t.Fatal("selection retained")
			}
			if name == "revision" && store.value.AuthorizationRevision != 2 {
				t.Fatal("revision retained")
			}
			if name == "unchanged" && store.writes != 0 {
				t.Fatal("unnecessary write")
			}
		})
	}
}

type readCipher struct {
	data []byte
	err  error
}

func (c readCipher) Seal([]byte, string) (Envelope, error) { return Envelope{}, nil }
func (c readCipher) Open(Envelope, string) ([]byte, error) { return append([]byte{}, c.data...), c.err }
func TestSessionReadStrictBoundariesAndIntegrity(t *testing.T) {
	now := time.Unix(2000000000, 0)
	csrf := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cookie := csrf
	for _, name := range []string{"valid", "malformed", "unknown", "idle_deadline", "absolute_deadline", "future", "wrong_generation", "wrong_policy", "cipher", "csrf"} {
		t.Run(name, func(t *testing.T) {
			p := Policy{SessionAbsoluteSeconds: 3600, SessionIdleSeconds: 1800}
			store := &readStore{value: ReadSession{FamilyID: "family", ActorID: "actor", PolicyVersion: "auth-test-v1", Generation: 1, CSRFHash: Digest(csrf), CreatedAt: now.Add(-time.Minute), FamilyCreatedAt: now.Add(-time.Minute), LastSeenAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour)}}
			data, _ := encodeSecrets("access", "refresh", csrf)
			cipher := readCipher{data: data}
			value := cookie
			switch name {
			case "malformed":
				value = "invalid"
			case "unknown":
				store.err = ErrSession
			case "idle_deadline":
				store.value.IdleExpiresAt = now
			case "absolute_deadline":
				store.value.AbsoluteExpiresAt = now
			case "future":
				store.value.LastSeenAt = now.Add(time.Second)
			case "wrong_generation":
				store.value.Generation = 0
			case "wrong_policy":
				store.value.PolicyVersion = "other"
			case "cipher":
				cipher.err = errors.New("unavailable key")
			case "csrf":
				store.value.CSRFHash = Digest("wrong")
			}
			s := SessionService{Store: store, Cipher: cipher, Policy: p, Now: func() time.Time { return now }}
			result, err := s.Read(context.Background(), value)
			if (err == nil) != (name == "valid") {
				t.Fatal("unexpected session authorization")
			}
			if err == nil && (result.AccessToken != "access" || result.CSRF != csrf) {
				t.Fatal("wrong secrets")
			}
			if name == "malformed" && store.calls != 0 {
				t.Fatal("malformed cookie queried storage")
			}
		})
	}
}
