CREATE TABLE auth_sessions (
    id           bigserial PRIMARY KEY,
    token_hash   bytea NOT NULL UNIQUE,
    user_id      bigint NOT NULL,
    method       text NOT NULL,
    login        text NOT NULL DEFAULT '',
    display_name text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    client_ip    text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT ''
);
CREATE INDEX auth_sessions_user_id_idx ON auth_sessions (user_id);
CREATE INDEX auth_sessions_expires_at_idx ON auth_sessions (expires_at);

CREATE TABLE auth_identities (
    issuer     text NOT NULL,
    subject    text NOT NULL,
    user_id    bigint NOT NULL,
    email      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX auth_identities_user_id_idx ON auth_identities (user_id);

CREATE TABLE auth_passwords (
    user_id         bigint PRIMARY KEY,
    username        text NOT NULL,
    hash            text NOT NULL,
    failed_attempts integer NOT NULL DEFAULT 0,
    last_failed_at  timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX auth_passwords_username_idx ON auth_passwords (lower(username));
