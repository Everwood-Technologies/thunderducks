//! Thunderducks CLI (`tducks`) — Wave E1.
//!
//! Talks to a local td-node HTTP RPC, or runs an in-process happy path.

use clap::{Parser, Subcommand};
use serde_json::Value;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "tducks", version, about = "Thunderducks CLI client")]
struct Cli {
    /// Base URL for local node RPC
    #[arg(long, global = true, default_value = "http://127.0.0.1:8788")]
    rpc: String,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print version
    Version,
    /// Run scripted happy path without network (CI)
    HappyPath,
    /// Start local node RPC server (blocks)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8788", env = "TD_BIND")]
        bind: String,
        /// Durable data dir (identity.key + claim.json). Falls back to $TD_DATA_DIR.
        #[arg(long, env = "TD_DATA_DIR")]
        data_dir: Option<std::path::PathBuf>,
        /// P2P listen bind (default 127.0.0.1:0). Use 0.0.0.0:0 for LAN/tailnet peers.
        #[arg(long, env = "TD_P2P_BIND")]
        p2p_bind: Option<String>,
        /// Host/IP advertised in rpc_base + p2p_uri (Tailscale IP or DNS).
        #[arg(long, env = "TD_ADVERTISE_HOST")]
        advertise_host: Option<String>,
        /// Untrusted assist relay URI (td://host:port).
        #[arg(long, env = "TD_RELAY_URI")]
        relay_uri: Option<String>,
        /// Require owner session for admin routes when bind is non-loopback (default true).
        #[arg(long, env = "TD_REQUIRE_OWNER", default_value_t = true)]
        require_owner: bool,
    },
    /// Show node status
    Status,
    /// Link a new secondary device (local approve)
    LinkDevice,
    /// List linked devices
    Devices,
    /// Remember a peer URI
    AddPeer { name: String, uri: String },
    /// Create a room
    CreateRoom { name: String },
    /// Send a text message
    Send { room_id: String, text: String },
    /// List messages in a room
    Recv { room_id: String },
    /// End-to-end CLI smoke against a temporary local RPC
    Smoke,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Commands::Version => {
            println!("tducks {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Commands::HappyPath => {
            let out = td_node::happy_path_script()?;
            println!("{out}");
            Ok(())
        }
        Commands::Serve {
            bind,
            data_dir,
            p2p_bind,
            advertise_host,
            relay_uri,
            require_owner,
        } => {
            let mut opts = td_node::ServeOptions::from_env();
            // CLI flags override env defaults when present.
            if data_dir.is_some() {
                opts.data_dir = data_dir;
            }
            if p2p_bind.is_some() {
                opts.p2p_bind = p2p_bind;
            }
            if advertise_host.is_some() {
                opts.advertise_host = advertise_host;
            }
            if relay_uri.is_some() {
                opts.relay_uri = relay_uri;
            }
            opts.require_owner_non_loopback = require_owner;
            td_node::serve_blocking_with_options(&bind, opts)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Commands::Status => {
            let v = get_json(&cli.rpc, "/v1/status").await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::LinkDevice => {
            let v = post_json(
                &cli.rpc,
                "/v1/devices/link-secondary",
                &serde_json::json!({}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::Devices => {
            let v = get_json(&cli.rpc, "/v1/devices").await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::AddPeer { name, uri } => {
            let v = post_json(
                &cli.rpc,
                "/v1/peers",
                &serde_json::json!({"name": name, "uri": uri}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::CreateRoom { name } => {
            let v = post_json(&cli.rpc, "/v1/rooms", &serde_json::json!({"name": name})).await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::Send { room_id, text } => {
            let v = post_json(
                &cli.rpc,
                "/v1/messages",
                &serde_json::json!({"room_id": room_id, "text": text}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::Recv { room_id } => {
            let v = post_json(
                &cli.rpc,
                "/v1/messages/list",
                &serde_json::json!({"room_id": room_id}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Commands::Smoke => run_smoke().await,
    }
}

async fn get_json(base: &str, path: &str) -> Result<Value, String> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

async fn post_json(base: &str, path: &str, body: &Value) -> Result<Value, String> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {text}"));
    }
    resp.json().await.map_err(|e| e.to_string())
}

async fn run_smoke() -> Result<(), String> {
    let addr = td_node::serve("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let base = format!("http://{addr}");
    // link
    let link = post_json(&base, "/v1/devices/link-secondary", &serde_json::json!({})).await?;
    if link["linked"] != true {
        return Err(format!("link failed: {link}"));
    }
    // peer
    let _ = post_json(
        &base,
        "/v1/peers",
        &serde_json::json!({"name": "alice", "uri": "td://127.0.0.1:1"}),
    )
    .await?;
    // room
    let room = post_json(&base, "/v1/rooms", &serde_json::json!({"name": "smoke"})).await?;
    let room_id = room["room_id"].as_str().ok_or("no room_id")?.to_string();
    // send
    let sent = post_json(
        &base,
        "/v1/messages",
        &serde_json::json!({"room_id": room_id, "text": "cli-smoke"}),
    )
    .await?;
    if sent.get("event_id").is_none() {
        return Err(format!("send failed: {sent}"));
    }
    // recv
    let msgs = post_json(
        &base,
        "/v1/messages/list",
        &serde_json::json!({"room_id": room_id}),
    )
    .await?;
    let text = msgs["messages"][0]["text"].as_str().unwrap_or("");
    if text != "cli-smoke" {
        return Err(format!("recv mismatch: {msgs}"));
    }
    let devices = get_json(&base, "/v1/devices").await?;
    println!(
        "smoke ok room={room_id} devices={} msg={}",
        devices["devices"].as_array().map(|a| a.len()).unwrap_or(0),
        sent["event_id"]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_version_const() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }

    #[test]
    fn happy_path_unit() {
        let out = td_node::happy_path_script().unwrap();
        assert!(out.starts_with("ok "));
    }

    #[tokio::test]
    async fn cli_smoke_against_temp_rpc() {
        run_smoke().await.unwrap();
    }
}
