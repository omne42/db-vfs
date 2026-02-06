//! HTTP service layer for `db-vfs`.
//!
//! - `policy_io`: policy loading + trust mode validation
//! - `server`: Axum router, middleware, auth, audit and execution plumbing

pub mod policy_io;
pub mod server;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum TrustMode {
    /// Trusted policy source; allows full configured feature set.
    Trusted,
    /// Untrusted policy source; applies strict safe subset constraints.
    Untrusted,
}

impl TrustMode {
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}
