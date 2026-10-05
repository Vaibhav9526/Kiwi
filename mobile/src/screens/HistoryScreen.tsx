/**
 * History screen (T-194) — the local decision log from `DecisionHistory`.
 *
 * What was decided (approve / deny / expired), when, against which
 * event/session, and how delivery ended. A timeout reads as `expired`,
 * never as `deny` (contract §6.3). Newest first, bounded to 256 entries,
 * rendered with short wire ids — full nonces/payloads are never echoed.
 */
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { EVENT_PHRASES } from '../protocol/approval';
import type { HistoryDecision, HistoryEntry } from '../protocol/history';
import type { ApprovalBundle } from '../environment';
import { fmtTime, shortId } from './format';

interface HistoryScreenProps {
  bundle: ApprovalBundle;
}

const DECISION_STYLE: Record<HistoryDecision, { label: string; color: string }> = {
  approve: { label: 'APPROVE', color: '#6fd29a' },
  deny: { label: 'DENY', color: '#e07a7a' },
  expired: { label: 'EXPIRED', color: '#e0a34a' },
};

const DELIVERY_NOTE: Record<HistoryEntry['delivery'], string> = {
  queued: 'queued',
  delivered: 'delivered',
  offline: 'not delivered (offline, will retry)',
  dropped: 'dropped by deny-TTL',
  'not-queued': 'no response sent',
};

function EntryRow(props: { entry: HistoryEntry }): React.JSX.Element {
  const { entry } = props;
  const badge = DECISION_STYLE[entry.decision];
  return (
    <View style={styles.row}>
      <Text style={[styles.badge, { color: badge.color }]}>{badge.label}</Text>
      <View style={styles.rowBody}>
        <Text style={styles.rowTitle}>{EVENT_PHRASES[entry.event]}</Text>
        <Text style={styles.rowMeta}>
          {fmtTime(entry.atUnix)} · {shortId(entry.challengeId)} · session {shortId(entry.sessionId, 16)}
        </Text>
        <Text style={styles.rowMeta}>{DELIVERY_NOTE[entry.delivery]}</Text>
      </View>
    </View>
  );
}

export function HistoryScreen(props: HistoryScreenProps): React.JSX.Element {
  const entries = props.bundle.history.entries();
  return (
    <View>
      <Text style={styles.h2}>Decision history</Text>
      <Text style={styles.p}>
        {entries.length} entr{entries.length === 1 ? 'y' : 'ies'} (newest first, local only) ·
        awaiting delivery: {props.bundle.service.queuedCount}
      </Text>
      {entries.length === 0 ? (
        <Text style={styles.empty}>
          No decisions yet — approve or deny a request from the Approvals tab.
        </Text>
      ) : (
        entries.map((e) => <EntryRow key={e.challengeId} entry={e} />)
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: '#e8edf2', fontSize: 17, fontWeight: '600', marginBottom: 8 },
  p: { color: '#aebccb', fontSize: 13, marginBottom: 12 },
  empty: { color: '#7a8a99', fontSize: 13 },
  row: {
    flexDirection: 'row',
    backgroundColor: '#1c232b',
    borderRadius: 8,
    padding: 10,
    marginBottom: 8,
    borderColor: '#2c3945',
    borderWidth: 1,
    gap: 10,
  },
  badge: { fontSize: 11, fontWeight: '700', width: 74, marginTop: 2 },
  rowBody: { flex: 1 },
  rowTitle: { color: '#e8edf2', fontSize: 13, fontWeight: '600' },
  rowMeta: { color: '#7a8a99', fontSize: 11, marginTop: 2 },
});
