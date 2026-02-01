use std::net::SocketAddr;

use clap::{ArgGroup, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "db-vfs-service",
    group(
        ArgGroup::new("db")
            .required(true)
            .multiple(false)
            .args(["sqlite", "postgres"])
    )
)]
struct Args {
    /// Bind address, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// SQLite database file path (created if missing)
    #[arg(long)]
    sqlite: Option<std::path::PathBuf>,

    /// Postgres connection string, e.g. postgres://user:pass@localhost:5432/db
    #[cfg_attr(not(feature = "postgres"), arg(hide = true))]
    #[arg(long)]
    postgres: Option<String>,

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

    let app = if let Some(url) = args.postgres {
        #[cfg(feature = "postgres")]
        {
            db_vfs_service::server::build_app_postgres(url, policy)?
        }
        #[cfg(not(feature = "postgres"))]
        {
            anyhow::bail!(
                "db-vfs-service was built without Postgres support; rebuild with `--features postgres`"
            );
        }
    } else {
        let sqlite = args.sqlite.expect("clap enforces exactly one DB backend");
        db_vfs_service::server::build_app_sqlite(sqlite, policy)?
    };
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
