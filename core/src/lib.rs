//! Core policy/path/redaction primitives for `db-vfs`.
//!
//! This crate defines stable, backend-agnostic building blocks:
//! - path/workspace validation
//! - policy schema + validation
//! - secret redaction and traversal skip matchers
//! - shared error model

#![forbid(unsafe_code)]

mod error;

pub mod glob_utils;
pub mod path;
pub mod policy;
pub mod redaction;
pub mod traversal;

pub use error::{Error, Result};
