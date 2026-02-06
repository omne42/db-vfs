use std::net::SocketAddr;

use clap::{ArgGroup, Parser};

use db_vfs_service::TrustMode;

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
    #[cfg_attr(not(feature = "postgres"), arg(hide = false))]
    #[arg(long)]
    postgres: Option<String>,

    /// Policy file path (.toml or .json), parsed as db_vfs_core::policy::VfsPolicy.
    #[arg(long)]
    policy: std::path::PathBuf,

    /// Trust mode for loading policy/configuration.
    ///
    /// - `trusted`: normal operation (default).
    /// - `untrusted`: refuse risky policy features (env interpolation, env-backed tokens, writes, full scans, audit path, and unsafe-no-auth).
    #[arg(long, value_enum, default_value_t = TrustMode::Trusted)]
    trust_mode: TrustMode,

    /// Allow unauthenticated requests (unsafe; local dev only).
    #[arg(long)]
    unsafe_no_auth: bool,

    /// Allow `--unsafe-no-auth` when binding to a non-loopback address (DANGEROUS).
    #[arg(long)]
    unsafe_no_auth_allow_non_loopback: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.unsafe_no_auth_allow_non_loopback && !args.unsafe_no_auth {
        anyhow::bail!("--unsafe-no-auth-allow-non-loopback requires --unsafe-no-auth");
    }
    if args.unsafe_no_auth
        && !args.listen.ip().is_loopback()
        && !args.unsafe_no_auth_allow_non_loopback
    {
        anyhow::bail!(
            "--unsafe-no-auth is only permitted when binding to a loopback address (listen={}). Use auth tokens, or if you really must, also pass --unsafe-no-auth-allow-non-loopback (DANGEROUS).",
            args.listen
        );
    }
    if args.unsafe_no_auth
        && args.unsafe_no_auth_allow_non_loopback
        && !args.listen.ip().is_loopback()
    {
        tracing::warn!(listen = %args.listen, "starting without auth on a non-loopback address (unsafe)");
    }
    let policy =
        db_vfs_service::policy_io::load_policy(&args.policy, args.trust_mode, args.unsafe_no_auth)?;

    let backend_kind = if args.postgres.is_some() {
        "postgres"
    } else {
        "sqlite"
    };

    let app = if let Some(url) = args.postgres {
        #[cfg(feature = "postgres")]
        {
            db_vfs_service::server::build_app_postgres(url, policy, args.unsafe_no_auth)?
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = url;
            anyhow::bail!(
                "db-vfs-service was built without Postgres support; rebuild with `--features postgres`"
            );
        }
    } else {
        let Some(sqlite) = args.sqlite else {
            anyhow::bail!("missing --sqlite argument (clap should enforce exactly one DB backend)");
        };
        db_vfs_service::server::build_app_sqlite(sqlite, policy, args.unsafe_no_auth)?
    };
    tracing::info!(
        listen = %args.listen,
        trust_mode = ?args.trust_mode,
        unsafe_no_auth = args.unsafe_no_auth,
        backend = backend_kind,
        "starting db-vfs-service"
    );
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
