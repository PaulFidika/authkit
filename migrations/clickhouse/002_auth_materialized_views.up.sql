-- AuthKit materialized views
-- These must be created after the tables they reference (from 001_auth_login_events.up.sql)

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_user_last_seen_from_refreshes {{ON_CLUSTER}}
TO user_last_seen_current AS
SELECT
    user_id,
    occurred_at AS last_seen,
    ip_addr,
    user_agent,
    occurred_at AS version
FROM user_auth_refreshes;
