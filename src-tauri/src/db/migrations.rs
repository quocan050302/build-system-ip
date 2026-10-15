use rusqlite::{Connection, Result};

pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    // Ensure WAL mode and foreign key constraints
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS schema_version (
             version INTEGER PRIMARY KEY,
             applied_at TEXT NOT NULL
         );"
    )?;

    let current_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version;",
        [],
        |row| row.get(0)
    ).unwrap_or(0);

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

    Ok(())
}
