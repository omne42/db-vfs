use std::net::SocketAddr;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "db-vfs-service")]
struct Args {
    /// Bind address, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// SQLite database file path (created if missing)
    #[arg(long)]
    sqlite: std::path::PathBuf,

    /// Policy file path (.toml or .json), parsed as db_vfs_core::policy::VfsPolicy.
    #[arg(long)]
    policy: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let policy = db_vfs_service::policy_io::load_policy(&args.policy)?;

    let app = db_vfs_service::server::build_app(args.sqlite, policy)?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
