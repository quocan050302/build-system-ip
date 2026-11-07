use rusqlite::{Connection, Result};

pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    // Ensure WAL mode and foreign key constraints
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS schema_version (
             version INTEGER PRIMARY KEY,
             applied_at TEXT NOT NULL
         );",
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version;",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "
            CREATE TABLE environments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                hypervisor_type TEXT NOT NULL,
                vm_identifier TEXT NOT NULL,
                guest_os TEXT NOT NULL,
                cpu_count INTEGER NOT NULL,
                memory_mb INTEGER NOT NULL,
                disk_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX idx_environments_status ON environments(status);

            CREATE TABLE network_endpoints (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                provider_label TEXT,
                host TEXT,
                port INTEGER,
                encrypted_secret_reference TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE environment_networks (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
                network_endpoint_id TEXT NOT NULL REFERENCES network_endpoints(id) ON DELETE CASCADE,
                policy_config TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(environment_id, network_endpoint_id)
            );

            CREATE TABLE network_checks (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
                observed_ipv4 TEXT,
                observed_ipv6 TEXT,
                dns_summary TEXT,
                check_source TEXT NOT NULL,
                status TEXT NOT NULL,
                checked_at TEXT NOT NULL
            );

            CREATE INDEX idx_network_checks_env ON network_checks(environment_id, checked_at DESC);

            CREATE TABLE browser_profiles (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL UNIQUE REFERENCES environments(id) ON DELETE CASCADE,
                browser_type TEXT NOT NULL,
                profile_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE channels (
                id TEXT PRIMARY KEY,
                youtube_channel_id TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
                authorization_status TEXT NOT NULL,
                content_review_status TEXT NOT NULL,
                last_reviewed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX idx_channels_env ON channels(environment_id);

            CREATE TABLE activity_logs (
                id TEXT PRIMARY KEY,
                environment_id TEXT,
                action TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX idx_activity_logs_created ON activity_logs(created_at DESC);

            CREATE TABLE application_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            INSERT INTO schema_version (version, applied_at) 
            VALUES (1, datetime('now'));
            "
        )?;
        tx.commit()?;
    }

    if current_version < 2 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "
            ALTER TABLE environments ADD COLUMN host_platform TEXT NOT NULL DEFAULT 'windows-x86_64';
            ALTER TABLE environments ADD COLUMN vm_architecture TEXT NOT NULL DEFAULT 'x86_64';
            ALTER TABLE environments ADD COLUMN provisioning_status TEXT NOT NULL DEFAULT 'COMPLETED';
            ALTER TABLE environments ADD COLUMN persistent_disk_reference TEXT;
            ALTER TABLE environments ADD COLUMN network_diagnostics_capability TEXT NOT NULL DEFAULT 'DIRECT_PROBE';

            ALTER TABLE network_checks ADD COLUMN latency_ms INTEGER;
            ALTER TABLE network_checks ADD COLUMN egress_stage TEXT NOT NULL DEFAULT 'NOT_CHECKED';

            INSERT INTO schema_version (version, applied_at) 
            VALUES (2, datetime('now'));
            "
        )?;
        tx.commit()?;
    }

    if current_version < 3 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "
            ALTER TABLE environments ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'VM';
            ALTER TABLE environments ADD COLUMN startup_url TEXT NOT NULL DEFAULT 'https://studio.youtube.com';
            ALTER TABLE environments ADD COLUMN preferred_language TEXT NOT NULL DEFAULT 'en-US';
            ALTER TABLE environments ADD COLUMN us_content_preferences INTEGER NOT NULL DEFAULT 1;

            ALTER TABLE browser_profiles ADD COLUMN startup_url TEXT NOT NULL DEFAULT 'https://studio.youtube.com';
            ALTER TABLE browser_profiles ADD COLUMN preferred_language TEXT NOT NULL DEFAULT 'en-US';
            ALTER TABLE browser_profiles ADD COLUMN executable_path TEXT;
            ALTER TABLE browser_profiles ADD COLUMN active_pid INTEGER;
            ALTER TABLE browser_profiles ADD COLUMN proxy_bridge_port INTEGER;
            ALTER TABLE browser_profiles ADD COLUMN last_launched_at TEXT;
            ALTER TABLE browser_profiles ADD COLUMN session_status TEXT NOT NULL DEFAULT 'STOPPED';

            ALTER TABLE network_endpoints ADD COLUMN username TEXT;
            ALTER TABLE network_endpoints ADD COLUMN expected_country TEXT;
            ALTER TABLE network_endpoints ADD COLUMN expected_ip TEXT;
            ALTER TABLE network_endpoints ADD COLUMN expires_at TEXT;

            ALTER TABLE network_checks ADD COLUMN observed_country TEXT;
            ALTER TABLE network_checks ADD COLUMN dns_leak_status TEXT NOT NULL DEFAULT 'UNVERIFIED';
            ALTER TABLE network_checks ADD COLUMN webrtc_status TEXT NOT NULL DEFAULT 'UNVERIFIED';
            ALTER TABLE network_checks ADD COLUMN proxy_auth_status TEXT;
            ALTER TABLE network_checks ADD COLUMN session_id TEXT;
            ALTER TABLE network_checks ADD COLUMN error_details TEXT;

            ALTER TABLE channels ADD COLUMN platform TEXT NOT NULL DEFAULT 'YouTube';
            ALTER TABLE channels ADD COLUMN workspace_name TEXT NOT NULL DEFAULT 'Alexa Creator Studio';
            ALTER TABLE channels ADD COLUMN account_handle TEXT;
            ALTER TABLE channels ADD COLUMN profile_url TEXT;
            ALTER TABLE channels ADD COLUMN analytics_url TEXT;
            ALTER TABLE channels ADD COLUMN gumroad_url TEXT;
            ALTER TABLE channels ADD COLUMN utm_source TEXT;
            ALTER TABLE channels ADD COLUMN utm_medium TEXT;
            ALTER TABLE channels ADD COLUMN utm_campaign TEXT;

            INSERT INTO schema_version (version, applied_at)
            VALUES (3, datetime('now'));
            "
        )?;
        tx.commit()?;
    }

    Ok(())
}
