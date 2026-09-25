//! Account commands: list/add/remove, one-shot server verification
//! (setup wizard, KIWI-UI-019), and connect-test for a stored account.
//!
//! Every established connection ends through `observe::record_connection` —
//! the trust engine and the finding feed see the real transport facts
//! before the UI hears an answer.

use std::sync::Arc;

use tauri::State;
use zeroize::Zeroizing;

use kiwi_core::session::{AuthMechanism, Protocol};
use kiwi_mail::account::{AuthRef, IncomingProtocol, MailAccount};
use kiwi_mail::imap::ImapClient;
use kiwi_mail::pop3::Pop3Client;
use kiwi_mail::smtp::SmtpClient;
use kiwi_mail::transport::{TlsSettings, Transport};

use super::{
    bounded, gate, parse_security, resolve_secret, run_mail_io, status_view, valid_addr, valid_host,
};
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AccountMeta, AppState, new_id};
use crate::types::{
    AccountView, AddAccountInput, AuthInput, SessionView, StepView, VerifyResult, VerifyServerInput,
};

const PALETTE: [&str; 6] = [
    "#2563eb", "#7a5b00", "#b23a22", "#0f766e", "#7c3aed", "#be185d",
];

#[tauri::command]
pub async fn kiwi_list_accounts(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<AccountView>> {
    gate(state.inner()).await?;
    list_accounts_impl(state.inner()).await
}

pub(crate) async fn list_accounts_impl(state: &AppState) -> CmdResult<Vec<AccountView>> {
    // Snapshot inputs first — locks never nest (refresh_trust's order:
    // index → devices → endpoint → sessions → trust).
    let (ids, folder_map) = {
        let index = state.index.lock().await;
        (index.account_ids.clone(), index.folders.clone())
    };
    let severities: std::collections::BTreeMap<String, Vec<kiwi_core::trust::SignalSeverity>> = {
        let sessions = state.sessions.lock().await;
        let mut m = std::collections::BTreeMap::new();
        for r in sessions.iter() {
            if let Some(id) = &r.session.account_id {
                m.entry(id.clone())
                    .or_insert_with(Vec::new)
                    .extend(r.signals.iter().map(|s| s.severity));
            }
        }
        m
    };
    let store = state.store.lock().await;
    let mut out = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        if let Some(acct) = store.get_account(id)? {
            let token = crate::types::account_trust_token(
                severities.get(id).into_iter().flatten().copied(),
            );
            let unread = unread_count(&store, folder_map.get(id));
            out.push(crate::types::account_view(
                &acct,
                token,
                unread,
                PALETTE[i % PALETTE.len()],
            ));
        }
    }
    Ok(out)
}

/// Unread = stored messages lacking `\Seen`. Bounded per folder.
fn unread_count(
    store: &kiwi_mail::store::MailStore,
    folders: Option<&Vec<crate::state::FolderEntry>>,
) -> u64 {
    let mut n = 0u64;
    for f in folders.into_iter().flatten() {
        if let Ok(msgs) = store.list_messages(f.id, 1000) {
            n += msgs
                .iter()
                .filter(|m| !m.flags.iter().any(|fl| fl == "\\Seen"))
                .count() as u64;
        }
    }
    n
}

/// Add an account. Secrets go straight to the OS credential store under a
/// generated `kiwi/<account_id>/<direction>` key — the account record (and
/// the DB row it serializes into) only ever holds the key name.
#[tauri::command]
pub async fn kiwi_add_account(
    state: State<'_, Arc<AppState>>,
    account: AddAccountInput,
) -> CmdResult<AccountView> {
    gate(state.inner()).await?;
    add_account_impl(state.inner(), account).await
}

pub(crate) async fn add_account_impl(
    state: &AppState,
    input: AddAccountInput,
) -> CmdResult<AccountView> {
    bounded("displayName", &input.display_name, 128)?;
    valid_addr("email", &input.email)?;
    bounded("username", input.username.as_deref().unwrap_or(""), 320)?;
    valid_host(&input.incoming.host)?;
    valid_host(&input.outgoing.host)?;
    if input.incoming.port == 0 || input.outgoing.port == 0 {
        return Err(IpcError::invalid("port must be 1..=65535"));
    }
    let in_security = parse_security(&input.incoming.security)?;
    let out_security = parse_security(&input.outgoing.security)?;
    let protocol = match input.incoming_protocol.as_str() {
        "imap" => IncomingProtocol::Imap,
        "pop3" => IncomingProtocol::Pop3,
        other => {
            return Err(IpcError::invalid(format!(
                "incomingProtocol must be imap|pop3, got {other:?}"
            )));
        }
    };

    // OAuth2 wizard seam (T-230): when an `oauth2Ticket` is referenced the
    // completed grant's `oauth2/<provider>/<email>` key replaces the
    // generated per-account key on BOTH directions — token material was
    // already persisted at poll-complete, so `store_secret` skips it.
    let oauth2_key = super::oauth2::oauth2_ticket_key(state, &input).await?;

    let account_id = new_id("acct");
    let username = input
        .username
        .clone()
        .unwrap_or_else(|| input.email.clone());
    let out_username = input
        .outgoing_username
        .clone()
        .unwrap_or_else(|| username.clone());

    let in_auth = auth_ref(
        &account_id,
        "in",
        input.incoming_auth.as_ref(),
        protocol == IncomingProtocol::Pop3,
        oauth2_key.as_deref(),
    )?;
    let out_auth = auth_ref(
        &account_id,
        "out",
        input.outgoing_auth.as_ref(),
        false, // SMTP has no POP3-only auth classes
        oauth2_key.as_deref(),
    )?;

    // Secrets into the OS store BEFORE the account row exists.
    store_secret(state, &in_auth, input.incoming_auth.as_ref())?;
    store_secret(state, &out_auth, input.outgoing_auth.as_ref())?;

    let acct = MailAccount {
        account_id: account_id.clone(),
        display_name: input.display_name.clone(),
        email: input.email.clone(),
        incoming: kiwi_mail::account::IncomingAccount {
            protocol,
            server: kiwi_mail::account::ServerConfig {
                host: input.incoming.host.clone(),
                port: input.incoming.port,
                security: in_security,
            },
            auth: in_auth,
            username,
        },
        outgoing: kiwi_mail::account::OutgoingAccount {
            server: kiwi_mail::account::ServerConfig {
                host: input.outgoing.host.clone(),
                port: input.outgoing.port,
                security: out_security,
            },
            auth: out_auth,
            username: out_username,
        },
    };
    state.store.lock().await.upsert_account(&acct)?;
    // Grant consumed only once the account row exists — a failed add leaves
    // the ticket usable for a retry.
    if let Some(ticket) = input
        .incoming_auth
        .as_ref()
        .or(input.outgoing_auth.as_ref())
        .and_then(|a| a.oauth2_ticket.as_deref())
    {
        super::oauth2::consume_oauth2_ticket(state, ticket).await;
    }
    {
        let mut index = state.index.lock().await;
        if !index.account_ids.contains(&account_id) {
            index.account_ids.push(account_id.clone());
        }
        index.account_meta.insert(
            account_id.clone(),
            AccountMeta {
                accept_invalid_certs: input.accept_invalid_certs,
                remote_content_allowed: false,
                org_id: None,
            },
        );
        index.save(&state.data_dir)?;
    }
    // Kick the sync supervisor — the new account's live worker starts
    // now, not on the next 2 s reconcile tick (T-157-adjacent).
    state.kick_sync();
    state.audit.lock().await.record(
        "account-added",
        &format!("{} <{}>", acct.display_name, acct.email),
        crate::state::now_unix(),
    )?;
    Ok(crate::types::account_view(&acct, "unknown", 0, PALETTE[0]))
}

/// Build the `AuthRef` (key names are generated here — the renderer never
/// picks credential-store keys). `oauth2_key` is the completed grant's
/// `oauth2/<provider>/<email>` key when the wizard bound a ticket — one
/// grant covers both directions, so both AuthRefs carry it. `is_pop3` is
/// the incoming-protocol check: `apop` requires it, `xoauth2` forbids it
/// (ipc.md §5 / audit IPC-10 — a POP3+XOAuth2 account would be unusable,
/// so it is rejected at add time, not discovered at connect).
fn auth_ref(
    account_id: &str,
    direction: &str,
    input: Option<&AuthInput>,
    is_pop3: bool,
    oauth2_key: Option<&str>,
) -> CmdResult<AuthRef> {
    let key = format!("kiwi/{account_id}/{direction}");
    match input.map(|a| a.kind.as_str()).unwrap_or("none") {
        "none" => Ok(AuthRef::None),
        "password" => Ok(AuthRef::Password {
            credential_key: key,
        }),
        "xoauth2" if is_pop3 => Err(IpcError::invalid("xoauth2 not supported on POP3")),
        "xoauth2" => Ok(AuthRef::XOAuth2 {
            credential_key: oauth2_key.map(str::to_string).unwrap_or(key),
        }),
        "apop" if is_pop3 => Ok(AuthRef::Apop {
            credential_key: key,
        }),
        "apop" => Err(IpcError::invalid("apop applies to POP3 only")),
        other => Err(IpcError::invalid(format!("unknown auth kind {other:?}"))),
    }
}

fn store_secret(state: &AppState, auth: &AuthRef, input: Option<&AuthInput>) -> CmdResult<()> {
    let key = match auth {
        AuthRef::None => return Ok(()),
        AuthRef::Password { credential_key }
        | AuthRef::XOAuth2 { credential_key }
        | AuthRef::Apop { credential_key } => credential_key,
    };
    // Ticket-bound grants already live under `oauth2/<provider>/<email>` —
    // nothing to store; an inline secret, if sent, is ignored rather than
    // written under a key nobody will read.
    if key.starts_with("oauth2/") {
        return Ok(());
    }
    let secret = input
        .and_then(|a| a.secret.as_deref())
        .ok_or_else(|| IpcError::invalid("auth kind requires a secret"))?;
    if secret.is_empty() || secret.len() > 4096 {
        return Err(IpcError::invalid("secret empty or over 4 KiB bound"));
    }
    state.credentials.set(key, secret)?;
    Ok(())
}

#[tauri::command]
pub async fn kiwi_remove_account(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    bounded("accountId", &account_id, 128)?;
    let state = state.inner();
    // Best-effort credential cleanup for the keys this layer generated.
    if let Some(acct) = state.store.lock().await.get_account(&account_id)? {
        for auth in [&acct.incoming.auth, &acct.outgoing.auth] {
            let key = match auth {
                AuthRef::Password { credential_key }
                | AuthRef::XOAuth2 { credential_key }
                | AuthRef::Apop { credential_key } => Some(credential_key.as_str()),
                AuthRef::None => Option::None,
            };
            if let Some(k) = key {
                let _ = state.credentials.delete(k);
            }
        }
    }
    let mut index = state.index.lock().await;
    let removed = index.account_ids.iter().position(|a| a == &account_id);
    if let Some(i) = removed {
        index.account_ids.remove(i);
    }
    index.account_meta.remove(&account_id);
    index.folders.remove(&account_id);
    index.save(&state.data_dir)?;
    drop(index);
    state.kick_sync(); // supervisor reaps the worker now, not next tick
    // MailStore::delete_account (schema v2) cascades folders/messages/
    // pop3_seen/outbox rows and sweeps on-disk payload dirs.
    state.store.lock().await.delete_account(&account_id)?;
    state
        .audit
        .lock()
        .await
        .record("account-removed", &account_id, crate::state::now_unix())?;
    Ok(serde_json::json!({ "removed": removed.is_some() }))
}

// ---------------------------------------------------------------------------
// Verification — the setup wizard probe and the stored-account test.
// ---------------------------------------------------------------------------

/// One-shot probe: connect to a server per protocol, optionally
/// authenticate, return the full observation + findings. Used by the setup
/// wizard before anything is persisted.
#[tauri::command]
pub async fn kiwi_verify_server(
    state: State<'_, Arc<AppState>>,
    input: VerifyServerInput,
) -> CmdResult<VerifyResult> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| verify_server_impl(s, input)).await
}

pub(crate) async fn verify_server_impl(
    state: Arc<AppState>,
    input: VerifyServerInput,
) -> CmdResult<VerifyResult> {
    valid_host(&input.server.host)?;
    if input.server.port == 0 {
        return Err(IpcError::invalid("port must be 1..=65535"));
    }
    let security = parse_security(&input.server.security)?;
    let protocol = match input.protocol.as_str() {
        "smtp" => Protocol::Smtp,
        "imap" => Protocol::Imap,
        "pop3" => Protocol::Pop3,
        other => return Err(IpcError::invalid(format!("unknown protocol {other:?}"))),
    };
    let settings = TlsSettings {
        accept_invalid_certs: input.accept_invalid_certs,
        extra_roots: Vec::new(),
    };
    // A probe never uses stored credentials — inline secret only.
    let secret = input
        .auth
        .as_ref()
        .and_then(|a| a.secret.as_deref().map(|s| Zeroizing::new(s.to_string())));
    let username = input.username.clone().unwrap_or_default();
    Ok(probe(
        &state,
        protocol,
        &input.server.host,
        input.server.port,
        security,
        settings,
        username,
        input.auth.as_ref(),
        secret,
        None,
        "verify",
    )
    .await)
}

/// Connect + authenticate a stored account's incoming AND outgoing server.
/// The full connect-test for settings / troubleshooting surfaces.
#[tauri::command]
pub async fn kiwi_test_account(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<Vec<VerifyResult>> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| test_account_impl(s, account_id)).await
}

pub(crate) async fn test_account_impl(
    state: Arc<AppState>,
    account_id: String,
) -> CmdResult<Vec<VerifyResult>> {
    bounded("accountId", &account_id, 128)?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(&account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;
    let accept_invalid = state
        .index
        .lock()
        .await
        .account_meta
        .get(&account_id)
        .map(|m| m.accept_invalid_certs)
        .unwrap_or(false);
    let settings = TlsSettings {
        accept_invalid_certs: accept_invalid,
        extra_roots: Vec::new(),
    };

    // Incoming.
    let in_proto = match acct.incoming.protocol {
        IncomingProtocol::Imap => Protocol::Imap,
        IncomingProtocol::Pop3 => Protocol::Pop3,
    };
    let in_secret = resolve_secret(&state, &acct.incoming.auth)?;
    let in_auth = auth_input_from(&acct.incoming.auth);
    let mut results = vec![
        probe(
            &state,
            in_proto,
            &acct.incoming.server.host,
            acct.incoming.server.port,
            acct.incoming.server.security,
            settings.clone(),
            acct.incoming.username.clone(),
            in_auth.as_ref(),
            in_secret,
            Some(account_id.clone()),
            "incoming login",
        )
        .await,
    ];
    // Outgoing.
    let out_secret = resolve_secret(&state, &acct.outgoing.auth)?;
    let out_auth = auth_input_from(&acct.outgoing.auth);
    results.push(
        probe(
            &state,
            Protocol::Smtp,
            &acct.outgoing.server.host,
            acct.outgoing.server.port,
            acct.outgoing.server.security,
            settings,
            acct.outgoing.username.clone(),
            out_auth.as_ref(),
            out_secret,
            Some(account_id.clone()),
            "smtp connect",
        )
        .await,
    );
    Ok(results)
}

/// Re-express a stored `AuthRef` as an `AuthInput` (kind only — the secret
/// is resolved separately through the credential store).
fn auth_input_from(auth: &AuthRef) -> Option<AuthInput> {
    let kind = match auth {
        AuthRef::None => return Option::None,
        AuthRef::Password { .. } => "password",
        AuthRef::XOAuth2 { .. } => "xoauth2",
        AuthRef::Apop { .. } => "apop",
    };
    Some(AuthInput {
        kind: kind.to_string(),
        secret: Option::None,
        oauth2_ticket: None,
    })
}

/// The shared connect/auth/observe core for `verify_server` and
/// `test_account`. Never returns `Err` after the input-validation stage —
/// a failed probe is a legitimate result (`ok: false` + failing step),
/// not an IPC error.
#[allow(clippy::too_many_arguments)]
async fn probe(
    state: &AppState,
    protocol: Protocol,
    host: &str,
    port: u16,
    security: kiwi_mail::transport::SocketSecurity,
    settings: TlsSettings,
    username: String,
    auth: Option<&AuthInput>,
    secret: Option<Zeroizing<String>>,
    account_id: Option<String>,
    label: &'static str,
) -> VerifyResult {
    let mut steps: Vec<StepView> = Vec::new();
    /// Evaluate `$fut`; on Ok push a passing step and yield the value; on Err
    /// push a failing step and return the whole probe as `ok:false`.
    macro_rules! try_step {
        ($stage:literal, $detail:expr, $fut:expr) => {
            match $fut.await {
                Ok(v) => {
                    steps.push(StepView {
                        stage: $stage.into(),
                        ok: true,
                        detail: $detail,
                    });
                    v
                }
                Err(e) => {
                    steps.push(StepView {
                        stage: $stage.into(),
                        ok: false,
                        detail: e.to_string(),
                    });
                    return VerifyResult {
                        ok: false,
                        steps,
                        session: Option::None,
                        findings: vec![],
                        trust: status_view(state).await,
                    };
                }
            }
        };
    }

    let transport = try_step!(
        "connect",
        format!("{host}:{port}"),
        Transport::connect(host, port, security, settings)
    );

    match protocol {
        Protocol::Smtp => {
            let mut client = try_step!(
                "smtp-handshake",
                "EHLO ok".to_string(),
                SmtpClient::connect(transport, kiwi_mail::smtp::SmtpConfig::default())
            );
            let offered = client.ehlo_info().map(|e| e.has_starttls());
            let auth_succeeded = match (auth, secret) {
                (Some(a), Some(s)) if a.kind != "none" => {
                    let sauth = smtp_auth(&a.kind, &username, s);
                    match client.authenticate(&sauth).await {
                        Ok(()) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: true,
                                detail: format!("{} authenticated", a.kind),
                            });
                            Some(true)
                        }
                        Err(e) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: false,
                                detail: e.to_string(),
                            });
                            Some(false)
                        }
                    }
                }
                _ => Option::None,
            };
            let facts = observe::facts_of(client.transport());
            let (record, _eval) = observe::record_connection(
                state,
                facts,
                ObservationContext {
                    protocol,
                    account_id,
                    starttls_offered: offered,
                    auth_mechanism: smtp_mech(auth),
                    auth_succeeded,
                    label,
                },
            )
            .await;
            let _ = client.quit().await;
            finish(state, steps, record).await
        }
        Protocol::Imap => {
            let mut client = try_step!(
                "imap-handshake",
                "greeting + CAPABILITY ok".to_string(),
                ImapClient::connect(transport)
            );
            let offered = Some(client.has_capability("STARTTLS"));
            let auth_succeeded = match (auth, secret) {
                (Some(a), Some(s)) if a.kind != "none" => match imap_auth(&a.kind, &username, s) {
                    Ok(iauth) => match client.authenticate(&iauth).await {
                        Ok(()) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: true,
                                detail: format!("{} authenticated", a.kind),
                            });
                            Some(true)
                        }
                        Err(e) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: false,
                                detail: e.to_string(),
                            });
                            Some(false)
                        }
                    },
                    Err(e) => {
                        steps.push(StepView {
                            stage: "auth".into(),
                            ok: false,
                            detail: e.to_string(),
                        });
                        Some(false)
                    }
                },
                _ => Option::None,
            };
            let facts = observe::facts_of(client.transport());
            let (record, _eval) = observe::record_connection(
                state,
                facts,
                ObservationContext {
                    protocol,
                    account_id,
                    starttls_offered: offered,
                    auth_mechanism: imap_mech(auth),
                    auth_succeeded,
                    label,
                },
            )
            .await;
            let _ = client.logout().await;
            finish(state, steps, record).await
        }
        Protocol::Pop3 => {
            let mut client = try_step!(
                "pop3-handshake",
                "greeting + CAPA ok".to_string(),
                Pop3Client::connect(transport, kiwi_mail::pop3::Pop3Config::default())
            );
            let offered = Some(client.has_capa("STLS"));
            let auth_succeeded = match (auth, secret) {
                (Some(a), Some(s)) if a.kind != "none" => match pop3_auth(&a.kind, &username, s) {
                    Ok(pauth) => match client.authenticate(&pauth).await {
                        Ok(()) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: true,
                                detail: format!("{} authenticated", a.kind),
                            });
                            Some(true)
                        }
                        Err(e) => {
                            steps.push(StepView {
                                stage: "auth".into(),
                                ok: false,
                                detail: e.to_string(),
                            });
                            Some(false)
                        }
                    },
                    Err(e) => {
                        steps.push(StepView {
                            stage: "auth".into(),
                            ok: false,
                            detail: e.to_string(),
                        });
                        Some(false)
                    }
                },
                _ => Option::None,
            };
            let facts = observe::facts_of(client.transport());
            let (record, _eval) = observe::record_connection(
                state,
                facts,
                ObservationContext {
                    protocol,
                    account_id,
                    starttls_offered: offered,
                    auth_mechanism: pop3_mech(auth),
                    auth_succeeded,
                    label,
                },
            )
            .await;
            let _ = client.quit().await;
            finish(state, steps, record).await
        }
    }
}

async fn finish(
    state: &AppState,
    mut steps: Vec<StepView>,
    record: crate::state::SessionRecord,
) -> VerifyResult {
    steps.push(StepView {
        stage: "evaluate".into(),
        ok: true,
        detail: format!("{} finding(s)", record.findings.len()),
    });
    let ok = steps.iter().all(|s| s.ok);
    VerifyResult {
        ok,
        steps,
        session: Some(SessionView::from(&record.session)),
        findings: record.findings,
        trust: status_view(state).await,
    }
}

// -- auth constructors -----------------------------------------------------

fn smtp_auth(kind: &str, user: &str, secret: Zeroizing<String>) -> kiwi_mail::smtp::SmtpAuth {
    match kind {
        "xoauth2" => kiwi_mail::smtp::SmtpAuth::XOAuth2 {
            user: user.to_string(),
            token: secret,
        },
        _ => kiwi_mail::smtp::SmtpAuth::Plain {
            user: user.to_string(),
            password: secret,
        },
    }
}

fn imap_auth(
    kind: &str,
    user: &str,
    secret: Zeroizing<String>,
) -> CmdResult<kiwi_mail::imap::ImapAuth> {
    match kind {
        "password" => Ok(kiwi_mail::imap::ImapAuth::Login {
            user: user.to_string(),
            password: secret,
        }),
        "xoauth2" => Ok(kiwi_mail::imap::ImapAuth::XOAuth2 {
            user: user.to_string(),
            token: secret,
        }),
        "apop" => Err(IpcError::invalid("apop applies to POP3 only")),
        other => Err(IpcError::invalid(format!("imap auth kind {other:?}"))),
    }
}

fn pop3_auth(
    kind: &str,
    user: &str,
    secret: Zeroizing<String>,
) -> CmdResult<kiwi_mail::pop3::Pop3Auth> {
    match kind {
        "apop" => Ok(kiwi_mail::pop3::Pop3Auth::Apop {
            user: user.to_string(),
            password: secret,
        }),
        "password" => Ok(kiwi_mail::pop3::Pop3Auth::UserPass {
            user: user.to_string(),
            password: secret,
        }),
        "xoauth2" => Err(IpcError::invalid("xoauth2 not supported on POP3 client")),
        other => Err(IpcError::invalid(format!("pop3 auth kind {other:?}"))),
    }
}

fn smtp_mech(auth: Option<&AuthInput>) -> AuthMechanism {
    match auth.map(|a| a.kind.as_str()) {
        Some("password") => AuthMechanism::Plain,
        Some("xoauth2") => AuthMechanism::XOAuth2,
        Some("apop") => AuthMechanism::Other("apop".into()),
        _ => AuthMechanism::None,
    }
}

fn imap_mech(auth: Option<&AuthInput>) -> AuthMechanism {
    match auth.map(|a| a.kind.as_str()) {
        Some("password") => AuthMechanism::Login,
        Some("xoauth2") => AuthMechanism::XOAuth2,
        _ => AuthMechanism::None,
    }
}

fn pop3_mech(auth: Option<&AuthInput>) -> AuthMechanism {
    match auth.map(|a| a.kind.as_str()) {
        Some("password") | Some("apop") => AuthMechanism::Plain,
        _ => AuthMechanism::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthInput, ServerInput};
    use std::time::Duration;

    fn acct_input() -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming_protocol: "imap".into(),
            incoming: ServerInput {
                host: "127.0.0.1".into(),
                port: 1,
                security: "tls".into(),
            },
            outgoing: ServerInput {
                host: "127.0.0.1".into(),
                port: 1,
                security: "tls".into(),
            },
            username: None,
            outgoing_username: None,
            incoming_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
                oauth2_ticket: None,
            }),
            outgoing_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
                oauth2_ticket: None,
            }),
            accept_invalid_certs: false,
        }
    }

    /// Account add registers the id AND pokes the supervisor's wake
    /// signal — the live worker starts without waiting for the tick.
    #[tokio::test(flavor = "current_thread")]
    async fn add_account_registers_and_kicks_supervisor() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-acct-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let view = add_account_impl(&state, acct_input()).await.unwrap();
        assert!(state.index.lock().await.account_ids.contains(&view.id));
        // The notify permit is stored — a waiter would return instantly.
        tokio::time::timeout(Duration::from_millis(50), state.sync_wakeup.notified())
            .await
            .expect("add_account_impl must kick the sync supervisor");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ipc.md §5 / audit IPC-10: xoauth2 is not a valid POP3 auth kind —
    /// rejected at add time so an unusable account never persists.
    #[tokio::test(flavor = "current_thread")]
    async fn xoauth2_rejected_for_pop3_at_add_time() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-acct-pop3xo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let mut input = acct_input();
        input.incoming_protocol = "pop3".into();
        input.incoming_auth.as_mut().unwrap().kind = "xoauth2".into();
        let err = add_account_impl(&state, input).await.unwrap_err();
        assert_eq!(err.code, "invalid-input");
        assert!(err.message.contains("POP3"), "{err:?}");
        assert!(state.index.lock().await.account_ids.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
