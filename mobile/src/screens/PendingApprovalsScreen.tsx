/**
 * Pending approvals screen (T-194; contract §4, §6, §7).
 *
 * Challenges arrive over the configured link (`pullChallenges`) with a
 * paste fallback for push-less Phase 4 delivery. Every review AND every
 * Approve/Deny tap runs the §6.1 gate order inside `ApprovalService`:
 * bounded parse -> live clock -> binding -> replay ledger. The screen never
 * re-implements a gate, never freezes the clock, and holds no crypto.
 *
 * Fail-closed posture: no paired identity => every action disabled
 * (AUTH-6); expiry is decided by the service at tap time and recorded as
 * `expired`, never `deny` (AUTH-7/AUTH-11); a keystore refusal surfaces
 * honestly and leaves the challenge re-approvable (rule 10).
 *
 * Demo affordances (mock mode only, feature-detected): generate a request,
 * toggle the mock desktop offline to show §7 best-effort retry.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { StyleSheet, Text, TextInput, TouchableOpacity, View } from 'react-native';

import { EVENT_PHRASES, type ReviewedChallenge } from '../protocol/approval';
import type { ChallengeData, PairedIdentity } from '../protocol/types';
import type { ApprovalBundle, Environment } from '../environment';
import { fmtTime, shortId } from './format';

export { EVENT_PHRASES as EVENT_LABELS };

interface ApprovalsScreenProps {
  environment: Environment;
  bundle: ApprovalBundle;
  identity: PairedIdentity | null;
}

const DEMO_EVENTS = [
  { event: 'unlock', label: 'Unlock' },
  { event: 'recovery', label: 'Recovery' },
  { event: 'elevated-action', label: 'Elevated' },
] as const;

export function PendingApprovalsScreen(props: ApprovalsScreenProps): React.JSX.Element {
  const { environment, bundle, identity } = props;
  const [list, setList] = useState<ChallengeData[]>([]);
  const [reviewed, setReviewed] = useState<ReviewedChallenge | null>(null);
  const [raw, setRaw] = useState('');
  const [status, setStatus] = useState('Pull requests from the desktop, or paste a challenge JSON.');
  const [busy, setBusy] = useState(false);
  const [, setTick] = useState(0);
  const [online, setOnline] = useState(true);

  // Live countdown: the service always uses its own clock; this only keeps
  // the displayed expiry honest while a reviewed challenge is on screen.
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const refresh = useCallback(async () => {
    if (identity === null) {return;}
    try {
      const pulled = await environment.link.pullChallenges(identity.deviceId);
      const fresh = pulled.filter(
        (c) => !bundle.ledger.isConsumed(c.challenge_id) && !list.some((p) => p.challenge_id === c.challenge_id),
      );
      if (fresh.length === 0) {
        setStatus('No new requests (unanswered and unexpired only).');
        return;
      }
      setList((prev) => [...prev, ...fresh]);
      setStatus(`${fresh.length} request(s) ready — open one to review it.`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'link unavailable';
      setStatus(`Pull failed (fail closed): ${msg.length > 140 ? `${msg.slice(0, 140)}…` : msg}`);
    }
  }, [bundle, environment, identity, list]);

  const openReview = useCallback(
    (challenge: ChallengeData) => {
      const res = bundle.service.review(JSON.stringify(challenge), identity);
      setList((prev) => prev.filter((c) => c.challenge_id !== challenge.challenge_id));
      if (!res.ok) {
        setStatus(`Rejected (${res.reason}): ${res.message}`);
        return;
      }
      setReviewed(res.reviewed);
      setStatus(`${EVENT_PHRASES[challenge.event]} requested — verify it on the desktop, then decide.`);
    },
    [bundle, identity],
  );

  const onReviewPaste = useCallback(() => {
    const res = bundle.service.review(raw, identity);
    if (!res.ok) {
      setStatus(`Rejected (${res.reason}): ${res.message}`);
      return;
    }
    setList((prev) => prev.filter((c) => c.challenge_id !== res.reviewed.challenge.challenge_id));
    setReviewed(res.reviewed);
    setStatus(`${EVENT_PHRASES[res.reviewed.challenge.event]} requested — verify it on the desktop.`);
    setRaw('');
  }, [bundle, identity, raw]);

  const onDecide = useCallback(
    async (decision: 'approve' | 'deny') => {
      if (reviewed === null || identity === null || busy) {return;}
      setBusy(true);
      try {
        const res = await bundle.service.decide(reviewed, identity, decision);
        if (!res.ok) {
          setStatus(`Blocked (${res.reason}): ${res.message}`);
          if (res.reason === 'expired' || res.reason === 'already-answered' || res.reason === 'wrong-device') {
            setReviewed(null);
          }
          return;
        }
        setReviewed(null);
        const flushed = await bundle.service.flush();
        const parts = [
          decision === 'approve' ? 'Approved (signed).' : 'Denied (unsigned).',
          `Delivered ${flushed.delivered.length}, offline ${flushed.offline.length}, dropped ${flushed.dropped.length}.`,
        ];
        setStatus(parts.join(' '));
      } finally {
        setBusy(false);
      }
    },
    [busy, bundle, identity, reviewed],
  );

  const onFlush = useCallback(async () => {
    if (busy) {return;}
    setBusy(true);
    try {
      const flushed = await bundle.service.flush();
      setStatus(
        `Queue drained: delivered ${flushed.delivered.length}, offline ${flushed.offline.length}, dropped ${flushed.dropped.length}.`,
      );
    } finally {
      setBusy(false);
    }
  }, [busy, bundle]);

  const onDemo = useCallback(
    (event: (typeof DEMO_EVENTS)[number]['event']) => {
      const issue = environment.demoIssueChallenge;
      if (identity === null || issue === undefined) {return;}
      issue(identity.deviceId, event);
      refresh().catch(() => undefined);
    },
    [environment, identity, refresh],
  );

  const toggleOnline = useCallback(() => {
    const next = !online;
    setOnline(next);
    environment.demoSetOnline?.(next);
    setStatus(next ? 'Mock desktop back online.' : 'Mock desktop offline — flushed outcomes will queue (§7).');
  }, [environment, online]);

  const secondsLeft =
    reviewed === null ? 0 : Math.max(0, reviewed.challenge.expires_unix - environment.clock.nowUnix());

  return (
    <View>
      <Text style={styles.h2}>Pending approvals</Text>
      {identity === null ? (
        <Text style={styles.warn}>
          No paired device — approvals are disabled (binding gate AUTH-6; pair first).
        </Text>
      ) : (
        <Text style={styles.p}>
          Device {identity.deviceId} · desktop {shortId(identity.desktopEndpoint, 28)}
        </Text>
      )}

      <View style={styles.row}>
        <TouchableOpacity
          style={[styles.button, styles.neutralBtn, identity === null || busy ? styles.buttonDisabled : null]}
          onPress={refresh}
          disabled={identity === null || busy}
          accessibilityRole="button"
        >
          <Text style={styles.buttonText}>Check requests</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, styles.neutralBtn, bundle.service.queuedCount === 0 || busy ? styles.buttonDisabled : null]}
          onPress={onFlush}
          disabled={bundle.service.queuedCount === 0 || busy}
          accessibilityRole="button"
        >
          <Text style={styles.buttonText}>Send queued ({bundle.service.queuedCount})</Text>
        </TouchableOpacity>
      </View>

      {environment.demoIssueChallenge !== undefined && (
        <View style={styles.row}>
          {DEMO_EVENTS.map((d) => (
            <TouchableOpacity
              key={d.event}
              style={[styles.button, styles.demoBtn, identity === null ? styles.buttonDisabled : null]}
              onPress={() => onDemo(d.event)}
              disabled={identity === null}
              accessibilityRole="button"
              accessibilityLabel={`Generate mock ${d.label} request`}
            >
              <Text style={styles.buttonText}>+ {d.label}</Text>
            </TouchableOpacity>
          ))}
          <TouchableOpacity
            style={[styles.button, styles.demoBtn, environment.demoSetOnline === undefined ? styles.buttonDisabled : null]}
            onPress={toggleOnline}
            disabled={environment.demoSetOnline === undefined}
            accessibilityRole="button"
          >
            <Text style={styles.buttonText}>{online ? 'Go offline' : 'Go online'}</Text>
          </TouchableOpacity>
        </View>
      )}

      {list.map((c) => (
        <TouchableOpacity
          key={c.challenge_id}
          style={styles.card}
          onPress={() => openReview(c)}
          accessibilityRole="button"
          accessibilityLabel={`Review ${EVENT_PHRASES[c.event]}`}
        >
          <Text style={styles.cardTitle}>{EVENT_PHRASES[c.event]}</Text>
          <Text style={styles.cardMeta}>
            {shortId(c.challenge_id)} · session {shortId(c.session_id, 16)} · expires {fmtTime(c.expires_unix)}
          </Text>
        </TouchableOpacity>
      ))}

      {reviewed !== null && (
        <View style={styles.reviewCard}>
          <Text style={styles.cardTitle}>{EVENT_PHRASES[reviewed.challenge.event]}</Text>
          <Text style={styles.cardMeta}>
            session {reviewed.challenge.session_id} · challenge {shortId(reviewed.challenge.challenge_id)} ·
            issued {fmtTime(reviewed.challenge.issued_unix)} · expires {fmtTime(reviewed.challenge.expires_unix)} (
            {secondsLeft}s left)
          </Text>
          <Text style={styles.p}>
            Verify this request on the desktop before approving. A denial confers no authorization;
            expiry is recorded as expired, never as a denial.
          </Text>
          <View style={styles.row}>
            <TouchableOpacity
              style={[styles.button, styles.denyBtn, busy ? styles.buttonDisabled : null]}
              onPress={() => onDecide('deny')}
              disabled={busy}
              accessibilityRole="button"
            >
              <Text style={styles.buttonText}>Deny</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.button, styles.approveBtn, busy || secondsLeft === 0 ? styles.buttonDisabled : null]}
              onPress={() => onDecide('approve')}
              disabled={busy || secondsLeft === 0}
              accessibilityRole="button"
            >
              <Text style={styles.buttonText}>Approve</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      <TextInput
        style={styles.input}
        multiline
        onChangeText={setRaw}
        value={raw}
        placeholder='{"schema_version":1,"challenge_id":"...",...}'
        placeholderTextColor="#5a6a78"
        accessibilityLabel="Challenge JSON"
        autoCapitalize="none"
        autoCorrect={false}
      />
      <TouchableOpacity
        style={[styles.button, styles.reviewBtn, identity === null ? styles.buttonDisabled : null]}
        onPress={onReviewPaste}
        disabled={identity === null}
        accessibilityRole="button"
      >
        <Text style={styles.buttonText}>Review pasted JSON</Text>
      </TouchableOpacity>

      <Text style={styles.status}>{status}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: '#e8edf2', fontSize: 17, fontWeight: '600', marginBottom: 8 },
  p: { color: '#aebccb', fontSize: 13, marginBottom: 12 },
  warn: { color: '#e0a34a', fontSize: 13, marginBottom: 12 },
  row: { flexDirection: 'row', gap: 8, marginBottom: 8 },
  button: { borderRadius: 8, padding: 11, alignItems: 'center', flex: 1 },
  neutralBtn: { backgroundColor: '#2c3945' },
  demoBtn: { backgroundColor: '#25303b' },
  reviewBtn: { backgroundColor: '#2c3945', marginBottom: 8 },
  approveBtn: { backgroundColor: '#2c7a4b' },
  denyBtn: { backgroundColor: '#8a3a3a' },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#ffffff', fontWeight: '600', fontSize: 12 },
  card: {
    backgroundColor: '#1c232b',
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
    borderColor: '#2c3945',
    borderWidth: 1,
  },
  reviewCard: {
    backgroundColor: '#1c232b',
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
    borderColor: '#2c7a4b',
    borderWidth: 1,
  },
  cardTitle: { color: '#e8edf2', fontSize: 14, fontWeight: '600' },
  cardMeta: { color: '#7a8a99', fontSize: 11, marginTop: 4, marginBottom: 6 },
  input: {
    minHeight: 72,
    borderColor: '#2c3945',
    borderWidth: 1,
    borderRadius: 8,
    color: '#e8edf2',
    padding: 10,
    marginBottom: 8,
    fontSize: 12,
  },
  status: { color: '#aebccb', marginTop: 4, fontSize: 12 },
});
