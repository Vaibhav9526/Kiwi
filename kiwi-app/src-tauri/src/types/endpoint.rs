//! Endpoint wire views — signal-collection report (commands/endpoint.rs).

use serde::Serialize;

use super::SecurityStatusView;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointReportView {
    pub collected_at_unix: i64,
    pub observations: Vec<crate::signals::EndpointObservation>,
    /// Full trust verdict after folding these signals in.
    pub status: SecurityStatusView,
}
