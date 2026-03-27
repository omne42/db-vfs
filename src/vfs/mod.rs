mod delete;
mod glob;
mod grep;
mod patch;
mod read;
mod util;
mod write;

use std::sync::Arc;

use db_vfs_core::policy::ValidatedVfsPolicy;
use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;
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
    policy: Arc<ValidatedVfsPolicy>,
    redactor: Arc<SecretRedactor>,
    traversal: Arc<TraversalSkipper>,
    store: S,
}

impl<S: Store> DbVfs<S> {
    fn build_matchers(policy: &ValidatedVfsPolicy) -> Result<(SecretRedactor, TraversalSkipper)> {
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;
        let traversal = TraversalSkipper::from_rules(&policy.traversal)?;
        Ok((redactor, traversal))
    }

    fn matcher_mismatch_error(kind: &str) -> Error {
        Error::InvalidPolicy(format!(
            "provided {kind} does not match the supplied policy; build matchers from the same policy"
        ))
    }

    fn ensure_redactor_matches_policy(
        policy: &ValidatedVfsPolicy,
        redactor: &SecretRedactor,
    ) -> Result<()> {
        if redactor.is_compatible_with_rules(&policy.secrets) {
            Ok(())
        } else {
            Err(Self::matcher_mismatch_error("SecretRedactor"))
        }
    }

    fn ensure_traversal_matches_policy(
        policy: &ValidatedVfsPolicy,
        traversal: &TraversalSkipper,
    ) -> Result<()> {
        if traversal.is_compatible_with_rules(&policy.traversal) {
            Ok(())
        } else {
            Err(Self::matcher_mismatch_error("TraversalSkipper"))
        }
    }

    pub fn new(store: S, policy: VfsPolicy) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        let (redactor, traversal) = Self::build_matchers(&policy)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_validated(store: S, policy: ValidatedVfsPolicy) -> Result<Self> {
        let (redactor, traversal) = Self::build_matchers(&policy)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_with_redactor(
        store: S,
        policy: VfsPolicy,
        redactor: SecretRedactor,
    ) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        Self::ensure_redactor_matches_policy(&policy, &redactor)?;
        let traversal = TraversalSkipper::from_rules(&policy.traversal)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_with_matchers(
        store: S,
        policy: VfsPolicy,
        redactor: SecretRedactor,
        traversal: TraversalSkipper,
    ) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        Self::ensure_redactor_matches_policy(&policy, &redactor)?;
        Self::ensure_traversal_matches_policy(&policy, &traversal)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_with_matchers_validated(
        store: S,
        policy: Arc<ValidatedVfsPolicy>,
        redactor: impl Into<Arc<SecretRedactor>>,
        traversal: impl Into<Arc<TraversalSkipper>>,
    ) -> Self {
        let redactor = redactor.into();
        let traversal = traversal.into();
        let (redactor, traversal) = if redactor.is_compatible_with_rules(&policy.secrets)
            && traversal.is_compatible_with_rules(&policy.traversal)
        {
            (redactor, traversal)
        } else {
            let (policy_redactor, policy_traversal) = Self::build_matchers(policy.as_ref())
                .expect("validated policy must build matchers");
            (Arc::new(policy_redactor), Arc::new(policy_traversal))
        };
        Self {
            policy,
            redactor,
            traversal,
            store,
        }
    }

    pub fn policy(&self) -> &VfsPolicy {
        self.policy.as_ref()
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
