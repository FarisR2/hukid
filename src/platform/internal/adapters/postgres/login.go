package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"hukid.local/platform/internal/authentication"
)

type LoginStore struct{ Pool *pgxpool.Pool }

// ValidateLoginDatabase confines this increment to an explicit laboratory DB.
func ValidateLoginDatabase(dsn string) error {
	config, err := pgx.ParseConfig(dsn)
	if err != nil || dsn == "" || !testTarget(config) {
		return errors.New("invalid laboratory database target")
	}
	return nil
}

func (s *LoginStore) CreateTransaction(ctx context.Context, t authentication.LoginTransaction) error {
	purpose := "login"
	var family, generation any
	if t.FamilyID != "" {
		purpose, family, generation = "step_up", t.FamilyID, t.Generation
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackLogin(tx)
	_, err = tx.Exec(ctx, `INSERT INTO console_auth.oidc_transactions(transaction_id,purpose,state_hash,nonce_hash,binding_hash,oidc_issuer,client_id,redirect_uri,return_to,verifier_ciphertext,verifier_nonce,verifier_key_version,created_at,expires_at,family_id,session_generation) VALUES($1,$14,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$15,$16)`, t.ID, t.StateHash, t.NonceHash, t.BindingHash, t.Issuer, t.ClientID, t.RedirectURI, t.ReturnTo, t.Verifier.Ciphertext, t.Verifier.Nonce, t.Verifier.KeyVersion, t.CreatedAt, t.ExpiresAt, purpose, family, generation)
	if err != nil {
		return err
	}
	action := "auth.login.started"
	if t.FamilyID != "" {
		action = "auth.step_up.started"
	}
	if err := appendAuthEvent(ctx, tx, action, "success", "", "", t.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *LoginStore) Consume(ctx context.Context, state, binding []byte, issuer, client, redirect string, now time.Time) (authentication.LoginTransaction, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return authentication.LoginTransaction{}, err
	}
	defer rollbackLogin(tx)
	var t authentication.LoginTransaction
	err = tx.QueryRow(ctx, `SELECT transaction_id::text,nonce_hash,return_to,verifier_ciphertext,verifier_nonce,verifier_key_version,created_at,expires_at,COALESCE(family_id::text,''),COALESCE(session_generation,0) FROM console_auth.oidc_transactions WHERE state_hash=$1 AND binding_hash=$2 AND oidc_issuer=$3 AND client_id=$4 AND redirect_uri=$5 AND consumed_at IS NULL AND created_at<=$6 AND expires_at>$6 FOR UPDATE`, state, binding, issuer, client, redirect, now).Scan(&t.ID, &t.NonceHash, &t.ReturnTo, &t.Verifier.Ciphertext, &t.Verifier.Nonce, &t.Verifier.KeyVersion, &t.CreatedAt, &t.ExpiresAt, &t.FamilyID, &t.Generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, authentication.ErrCallback
	}
	if err != nil {
		return t, err
	}
	t.Issuer = issuer
	t.ClientID = client
	t.RedirectURI = redirect
	result, err := tx.Exec(ctx, `UPDATE console_auth.oidc_transactions SET consumed_at=$2,verifier_ciphertext=NULL,verifier_nonce=NULL,verifier_key_version=NULL WHERE transaction_id=$1 AND consumed_at IS NULL`, t.ID, now)
	if err != nil {
		return authentication.LoginTransaction{}, err
	}
	if result.RowsAffected() != 1 {
		return authentication.LoginTransaction{}, authentication.ErrCallback
	}
	if err := tx.Commit(ctx); err != nil {
		return authentication.LoginTransaction{}, err
	}
	return t, nil
}

func (s *LoginStore) CreateInitialSession(ctx context.Context, v authentication.InitialSession) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackLogin(tx)
	var actor string
	if err = tx.QueryRow(ctx, `SELECT console_auth.register_operator($1,$2)::text`, v.Identity.Issuer, v.Identity.Subject).Scan(&actor); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO console_auth.session_families(family_id,operator_identity_id,created_at,absolute_expires_at,auth_time,amr,acr,original_grant,policy_version) VALUES($1,$2,$3,$4,$5,$6,$7,'authorization_code',$8)`, v.FamilyID, actor, v.CreatedAt, v.AbsoluteExpiresAt, v.Identity.AuthTime, v.Identity.AMR, v.Identity.ACR, v.PolicyVersion)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO console_auth.sessions(session_id,family_id,operator_identity_id,generation,cookie_hash,csrf_hash,created_at,last_seen_at,idle_expires_at,absolute_expires_at,secret_ciphertext,secret_nonce,secret_key_version,refresh_digest) VALUES($1,$2,$3,1,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12)`, v.SessionID, v.FamilyID, actor, v.CookieHash, v.CSRFHash, v.CreatedAt, v.IdleExpiresAt, v.AbsoluteExpiresAt, v.Secrets.Ciphertext, v.Secrets.Nonce, v.Secrets.KeyVersion, v.RefreshDigest)
	if err != nil {
		return err
	}
	if err := appendAuthEvent(ctx, tx, "auth.login.completed", "success", actor, "", v.FamilyID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func rollbackLogin(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx.Rollback(ctx)
}
