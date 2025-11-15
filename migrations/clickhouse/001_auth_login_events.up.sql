-- AuthKit: Login events (refresh session issued at login)
CREATE TABLE IF NOT EXISTS user_auth_logins {{ON_CLUSTER}} (
    occurred_at DateTime('UTC'),
    user_id String,
    method LowCardinality(String), -- password_login | oidc_login
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id, occurred_at, method)
SETTINGS index_granularity = 8192;

-- AuthKit: Refresh events (ID token issued via refresh)
CREATE TABLE IF NOT EXISTS user_auth_refreshes {{ON_CLUSTER}} (
    occurred_at DateTime('UTC'),
    user_id String,
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id, occurred_at)
SETTINGS index_granularity = 8192;

-- Current view (snapshot): last time a user obtained a refresh token (login or refresh)
CREATE TABLE IF NOT EXISTS user_last_seen_current {{ON_CLUSTER}} (
    user_id String,
    last_seen DateTime('UTC') DEFAULT now(),
    ip_addr Nullable(String),
    user_agent Nullable(String),
    version DateTime('UTC') DEFAULT now()
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{database}/{table}', '{replica}', version)
ORDER BY (user_id)
SETTINGS index_granularity = 8192;

-- Cleanup for older revisions that created the login-based MV
DROP VIEW IF EXISTS mv_user_last_seen_from_logins {{ON_CLUSTER}};
