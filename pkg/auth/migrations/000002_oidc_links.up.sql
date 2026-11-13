CREATE TABLE auth_oidc_links (
    state_hash bytea PRIMARY KEY,
    user_id    bigint NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_oidc_links_expires_at_idx ON auth_oidc_links (expires_at);
