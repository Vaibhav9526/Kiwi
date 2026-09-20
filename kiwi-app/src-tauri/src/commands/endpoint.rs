//! T-121 — endpoint signal collection command.
//!
//! Exempt from the lock gate: signals must keep flowing while locked —
//! they are how the trust engine learns the endpoint is still degraded
//! (unlock lands `Degraded` when active signals remain, per contract §4).

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tauri::State;

use super::status_view;
use crate::error::CmdResult;
use crate::signals;
use crate::state::AppState;
use crate::types::EndpointReportView;

/// Collect bounded endpoint indicators, persist their evidence, feed the
/// trust engine, and return the report + resulting status.
#[tauri::command]
pub async fn kiwi_collect_endpoint_signals(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<EndpointReportView> {
    collect_impl(state.inner()).await
}

pub(crate) async fn collect_impl(state: &AppState) -> CmdResult<EndpointReportView> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let probe = signals::probe_now();
    let baseline = signals::load_baseline(&state.data_dir);
    let (observations, new_baseline) = signals::collect(&probe, baseline.as_ref(), &COUNTER);
    if let Some(b) = new_baseline {
        signals::save_baseline(&state.data_dir, &b)?;
    }
    signals::persist_evidence(&state.data_dir, &observations)?;
    {
        let mut slot = state.endpoint_signals.lock().await;
        *slot = observations.iter().map(|o| o.as_signal().1).collect();
    }
    let _eval = state.refresh_trust().await;
    if !observations.is_empty() {
        state.audit.lock().await.record(
            "endpoint-signals",
            &format!("{} indicator(s) collected", observations.len()),
            crate::state::now_unix(),
        )?;
    }
    Ok(EndpointReportView {
        collected_at_unix: probe.now_unix,
        observations,
        status: status_view(state).await,
    })
}
