#![forbid(unsafe_code)]

//! `db-vfs` provides a policy-governed virtual filesystem backed by SQL stores.
//!
//! - `store`: backend trait + SQLite/Postgres implementations
//! - `vfs`: read/write/patch/delete/glob/grep operations with policy enforcement
//! - `migrations`: schema bootstrap helpers for supported backends

pub mod migrations;
pub mod store;
pub mod vfs;

pub use db_vfs_core::{Error, Result};
