CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used TIMESTAMPTZ,
    permission_level SMALLINT NOT NULL DEFAULT 0,
    name TEXT,
    description TEXT,
    github_user TEXT NOT NULL
);
