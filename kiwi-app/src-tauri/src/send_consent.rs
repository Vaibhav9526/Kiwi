use std::collections::VecDeque;
#[cfg(test)]
use std::sync::Mutex;

use rfd::{AsyncMessageDialog, MessageButtons, MessageDialogResult, MessageLevel};

pub const SEND_CONSENT_BURST_LIMIT: usize = 3;
pub const SEND_CONSENT_BURST_WINDOW_MS: i64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrationDestinationKind {
    TempInbox,
    DeliverabilityTest,
}

impl IntegrationDestinationKind {
    pub fn disclosure(self) -> &'static str {
        match self {
            Self::TempInbox => {
                "temporary public inbox operated by GuerrillaMail — readable by anyone who knows the address"
            }
            Self::DeliverabilityTest => {
                "third-party deliverability test service (email-spam-tester.com) — accepts one message per reservation"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationDestination {
    pub address: String,
    pub kind: IntegrationDestinationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationSendRequest {
    pub from: String,
    pub subject: String,
    pub destinations: Vec<IntegrationDestination>,
    pub attachment_count: usize,
    pub body_bytes: usize,
}

impl IntegrationSendRequest {
    pub fn disclosure(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for kind in self
            .destinations
            .iter()
            .map(|d| d.kind)
            .collect::<std::collections::BTreeSet<_>>()
        {
            parts.push(kind.disclosure());
        }
        parts.join("\n\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Approved,
    Denied,
}

#[async_trait::async_trait]
pub trait SendConsent: Send + Sync {
    async fn request(&self, request: &IntegrationSendRequest) -> ConsentDecision;
}

pub struct NativeSendConsent;

#[async_trait::async_trait]
impl SendConsent for NativeSendConsent {
    async fn request(&self, request: &IntegrationSendRequest) -> ConsentDecision {
        let destinations = request
            .destinations
            .iter()
            .map(|d| d.address.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let description = format!(
            "KIWI is about to send this message from {} to a third-party service.\n\nTo: {destinations}\nSubject: {}\nAttachments: {}\nMessage body: {} bytes\n\n{}\n\nThe destination address is managed by an external service, not your mail account.",
            one_line(&request.from),
            one_line(&request.subject),
            request.attachment_count,
            request.body_bytes,
            request.disclosure(),
        );
        let result = AsyncMessageDialog::new()
            .set_level(MessageLevel::Warning)
            .set_title("Confirm third-party send")
            .set_description(description)
            .set_buttons(MessageButtons::OkCancelCustom(
                "Send once".to_string(),
                "Cancel".to_string(),
            ))
            .show()
            .await;
        match result {
            MessageDialogResult::Custom(ref label) if label == "Send once" => {
                ConsentDecision::Approved
            }
            _ => ConsentDecision::Denied,
        }
    }
}

fn one_line(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars().take(160) {
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct ConsentBurstGuard {
    stamps_ms: VecDeque<i64>,
}

impl ConsentBurstGuard {
    pub fn admit(&mut self, now_ms: i64) -> bool {
        while self
            .stamps_ms
            .front()
            .is_some_and(|t| now_ms - *t >= SEND_CONSENT_BURST_WINDOW_MS)
        {
            self.stamps_ms.pop_front();
        }
        if self.stamps_ms.len() >= SEND_CONSENT_BURST_LIMIT {
            return false;
        }
        self.stamps_ms.push_back(now_ms);
        true
    }
}

#[cfg(test)]
pub struct FixedSendConsent {
    decision: ConsentDecision,
    requests: Mutex<Vec<IntegrationSendRequest>>,
}

#[cfg(test)]
impl FixedSendConsent {
    pub fn approving() -> Self {
        Self {
            decision: ConsentDecision::Approved,
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn denying() -> Self {
        Self {
            decision: ConsentDecision::Denied,
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<IntegrationSendRequest> {
        self.requests.lock().expect("consent requests").clone()
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl SendConsent for FixedSendConsent {
    async fn request(&self, request: &IntegrationSendRequest) -> ConsentDecision {
        self.requests
            .lock()
            .expect("consent requests")
            .push(request.clone());
        self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_guard_allows_three_then_denies_inside_window() {
        let mut guard = ConsentBurstGuard::default();
        assert!(guard.admit(1_000));
        assert!(guard.admit(1_001));
        assert!(guard.admit(1_002));
        assert!(!guard.admit(1_003));
        assert!(guard.admit(1_000 + SEND_CONSENT_BURST_WINDOW_MS));
    }

    #[test]
    fn disclosure_names_every_crossed_service() {
        let request = IntegrationSendRequest {
            from: "me@example.test".into(),
            subject: "hi".into(),
            destinations: vec![
                IntegrationDestination {
                    address: "a@sharklasers.com".into(),
                    kind: IntegrationDestinationKind::DeliverabilityTest,
                },
                IntegrationDestination {
                    address: "b@sharklasers.com".into(),
                    kind: IntegrationDestinationKind::TempInbox,
                },
            ],
            attachment_count: 0,
            body_bytes: 12,
        };
        let disclosure = request.disclosure();
        assert!(disclosure.contains("email-spam-tester.com"));
        assert!(disclosure.contains("GuerrillaMail"));
    }

    #[test]
    fn subject_is_single_line_and_bounded() {
        let value = "a\nb\tc".repeat(100);
        let out = one_line(&value);
        assert!(!out.contains('\n'));
        assert!(!out.contains('\t'));
        assert!(out.chars().count() <= 160);
    }
}
