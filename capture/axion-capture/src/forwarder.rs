use anyhow::Result;
use reqwest::Client;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Serialize, Clone)]
pub struct Alert {
    pub detector: String,
    pub title: String,
    pub severity: String,
    pub ts: f64,
    pub node_id: String,
    pub details: serde_json::Value,
}

/// HTTP forwarder with optional SQLite-backed persistent queue.
/// Mirrors the behaviour of `tacnet_sec/core/forwarder.py`.
pub struct Forwarder {
    server_url: String,
    api_key: String,
    node_id: String,
    client: Client,
    db: Option<Connection>,
}

impl Forwarder {
    pub async fn new(
        server_url: String,
        api_key: String,
        node_id: String,
        db_path: Option<String>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let db = match db_path {
            Some(path) => {
                let conn = Connection::open(&path)?;
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS pending_alerts (
                        id       INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload  TEXT    NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        delivered INTEGER NOT NULL DEFAULT 0,
                        ts       REAL    NOT NULL
                    );",
                )?;
                info!(path = %path, "Persistent alert queue opened");
                Some(conn)
            }
            None => None,
        };

        Ok(Forwarder {
            server_url,
            api_key,
            node_id,
            client,
            db,
        })
    }

    /// Submit an alert: try HTTP POST first; on failure persist to SQLite.
    pub async fn submit(&mut self, mut alert: Alert) -> Result<()> {
        alert.node_id = self.node_id.clone();

        let url = format!("{}/api/alerts", self.server_url);
        let result = self
            .client
            .post(&url)
            .header("X-Axion-Key", &self.api_key)
            .json(&alert)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!(detector = %alert.detector, severity = %alert.severity, "Alert forwarded");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                warn!(%status, "Server rejected alert — persisting for retry");
                self.persist(&alert)?;
                anyhow::bail!("Server returned {status}");
            }
            Err(e) => {
                warn!(err = %e, "Network error — persisting alert for retry");
                self.persist(&alert)?;
                Err(e.into())
            }
        }
    }

    /// Retry any undelivered rows persisted in SQLite.
    /// Called once on agent startup and periodically by a background task.
    pub async fn flush_pending(&mut self) -> Result<()> {
        let Some(db) = &self.db else { return Ok(()) };

        let ids_and_payloads: Vec<(i64, String)> = {
            let mut stmt = db.prepare(
                "SELECT id, payload FROM pending_alerts
                 WHERE delivered = 0 AND attempts < 10
                   AND ts > unixepoch() - 72*3600",
            )?;
            let x = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .filter_map(|r| r.ok())
                .collect();
            x
        };

        for (id, payload) in ids_and_payloads {
            let url = format!("{}/api/alerts", self.server_url);
            let ok = self
                .client
                .post(&url)
                .header("X-Axion-Key", &self.api_key)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);

            if ok {
                db.execute("UPDATE pending_alerts SET delivered = 1 WHERE id = ?1", params![id])?;
                info!(id, "Pending alert delivered");
            } else {
                db.execute(
                    "UPDATE pending_alerts SET attempts = attempts + 1 WHERE id = ?1",
                    params![id],
                )?;
            }
        }
        Ok(())
    }

    fn persist(&self, alert: &Alert) -> Result<()> {
        if let Some(db) = &self.db {
            let payload = serde_json::to_string(alert)?;
            db.execute(
                "INSERT INTO pending_alerts (payload, ts) VALUES (?1, ?2)",
                params![payload, alert.ts],
            )?;
        }
        Ok(())
    }
}
