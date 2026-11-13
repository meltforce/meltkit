CREATE TABLE auth_tokens (
    id           bigserial PRIMARY KEY,
    token_hash   bytea NOT NULL UNIQUE,
    user_id      bigint NOT NULL,
    name         text NOT NULL,
    scopes       text[] NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz,
    last_used_at timestamptz
);
CREATE INDEX auth_tokens_user_id_idx ON auth_tokens (user_id);
