//! NullProvider — always `Unavailable`. This is the correct answer when no
//! sandbox tier exists on a host: callers surface a capability gap and
//! NEVER fall back to host execution (ADR-008 invariant).

use crate::{Availability, Result, Sandbox, SandboxError, SandboxProvider, SandboxSpec};

pub struct NullProvider {
    reason: String,
}

impl NullProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait::async_trait]
impl SandboxProvider for NullProvider {
    fn availability(&self) -> Availability {
        Availability::Unavailable(self.reason.clone())
    }

    async fn create(&self, _spec: SandboxSpec) -> Result<Box<dyn Sandbox>> {
        Err(SandboxError::Unavailable(self.reason.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn null_provider_reports_unavailable_and_never_creates() {
        let p = NullProvider::new("no sandbox tier on this host");
        assert!(matches!(
            p.availability(),
            Availability::Unavailable(r) if r.contains("no sandbox tier")
        ));
        let err = p
            .create(SandboxSpec {
                artifact_path: PathBuf::from("x"),
                timeout_secs: 30,
                max_memory_mb: 256,
                allow_egress: false,
            })
            .await
            .err()
            .expect("NullProvider must never create");
        assert!(matches!(err, SandboxError::Unavailable(_)));
    }
}
