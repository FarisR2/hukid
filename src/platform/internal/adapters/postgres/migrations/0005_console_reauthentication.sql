SET LOCAL ROLE hukid_owner;
ALTER TABLE console_auth.oidc_transactions
  ADD COLUMN session_generation bigint,
  ADD CONSTRAINT transaction_generation CHECK (
    (purpose='login' AND session_generation IS NULL) OR
    (purpose='step_up' AND session_generation IS NOT NULL AND session_generation>0)),
  ADD CONSTRAINT transaction_session_generation FOREIGN KEY (family_id,session_generation)
    REFERENCES console_auth.sessions(family_id,generation);
