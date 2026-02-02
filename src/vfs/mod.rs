mod delete;
mod glob;
mod grep;
mod patch;
mod read;
mod util;
mod write;

use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::store::Store;

pub use delete::{DeleteRequest, DeleteResponse};
pub use glob::{GlobRequest, GlobResponse};
pub use grep::{GrepMatch, GrepRequest, GrepResponse};
pub use patch::{PatchRequest, PatchResponse};
pub use read::{ReadRequest, ReadResponse};
pub use write::{WriteRequest, WriteResponse};

#[derive(Debug)]
pub struct DbVfs<S> {
    policy: VfsPolicy,
    redactor: SecretRedactor,
    store: S,
}

impl<S: Store> DbVfs<S> {
    pub fn new(store: S, policy: VfsPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;
        Ok(Self {
            policy,
            redactor,
            store,
        })
    }

    pub fn new_with_redactor(
        store: S,
        policy: VfsPolicy,
        redactor: SecretRedactor,
    ) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            redactor,
            store,
        })
    }

    pub fn policy(&self) -> &VfsPolicy {
        &self.policy
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    Entries,
    Files,
    Time,
    Results,
}

impl<S: Store> DbVfs<S> {
    pub fn read(&mut self, request: ReadRequest) -> Result<ReadResponse> {
        read::read(self, request)
    }

    pub fn write(&mut self, request: WriteRequest) -> Result<WriteResponse> {
        write::write(self, request)
    }

    pub fn apply_unified_patch(&mut self, request: PatchRequest) -> Result<PatchResponse> {
        patch::apply_unified_patch(self, request)
    }

    pub fn delete(&mut self, request: DeleteRequest) -> Result<DeleteResponse> {
        delete::delete(self, request)
    }

    pub fn glob(&mut self, request: GlobRequest) -> Result<GlobResponse> {
        glob::glob(self, request)
    }

    pub fn grep(&mut self, request: GrepRequest) -> Result<GrepResponse> {
        grep::grep(self, request)
    }
}

impl<S> DbVfs<S> {
    fn ensure_allowed(&self, ok: bool, op: &str) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err(Error::NotPermitted(format!("{op} is disabled by policy")))
        }
    }
}
