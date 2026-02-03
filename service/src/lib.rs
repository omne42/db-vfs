pub mod policy_io;
pub mod server;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
#[clap(rename_all = "kebab_case")]
pub enum TrustMode {
    #[default]
    Trusted,
    Untrusted,
}
