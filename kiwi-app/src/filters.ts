/**
 * Thunderbird-style mail filters (T-186): pure client-side rule engine. No
 * backend filter store exists, so rules live in prefs (`kiwi.filterRules`,
 * pushed via the prefs chain when it lands) and "run" applies matching
 * actions to already-loaded messages through the real bulk commands
 * (mark-read/star/archive via kiwi_update_message, delete via
 * kiwi_delete_messages). Conditions AND together; rules run in list order.
 *
 * Envelope limits (stated in-view): there is no per-message recipients
 * field on the wire, so `to` matches the account address; matching is a
 * case-insensitive substring ("contains").
 */

import type { MessageEnvelope } from "./kiwi";

export type RuleField = "from" | "to" | "subject";
export type RuleAction = "mark-read" | "star" | "archive" | "delete";

export const RULE_FIELDS: RuleField[] = ["from", "to", "subject"];
export const RULE_ACTIONS: RuleAction[] = ["mark-read", "star", "archive", "delete"];

export interface RuleCondition {
  field: RuleField;
  value: string;
}

export interface FilterRule {
  id: string;
  name: string;
  enabled: boolean;
  /** Account scope, or null for all accounts. */
  accountId: string | null;
  conditions: RuleCondition[];
  actions: RuleAction[];
}

let ruleSeq = 0;

export function newRule(): FilterRule {
  ruleSeq += 1;
  return {
    id: `rule-${Date.now().toString(36)}-${ruleSeq}`,
    name: "New rule",
    enabled: true,
    accountId: null,
    conditions: [{ field: "from", value: "" }],
    actions: ["mark-read"],
  };
}

function fieldText(m: MessageEnvelope, field: RuleField): string {
  switch (field) {
    case "from":
      return m.from;
    case "to":
      return m.accountEmail;
    case "subject":
      return m.subject;
  }
}

/** True when every non-blank condition contains-matches (account in scope). */
export function matchRule(rule: FilterRule, m: MessageEnvelope): boolean {
  if (!rule.enabled) return false;
  if (rule.accountId && m.accountId !== rule.accountId) return false;
  const conds = rule.conditions.filter((c) => c.value.trim());
  if (conds.length === 0 || rule.actions.length === 0) return false;
  return conds.every((c) => fieldText(m, c.field).toLowerCase().includes(c.value.trim().toLowerCase()));
}

export function describeRule(rule: FilterRule, emailOf: (id: string) => string): string {
  const conds =
    rule.conditions
      .filter((c) => c.value.trim())
      .map((c) => `${c.field} contains "${c.value.trim()}"`)
      .join(" AND ") || "no conditions";
  const scope = rule.accountId ? ` [${emailOf(rule.accountId)}]` : "";
  return `${conds} → ${rule.actions.join(", ")}${scope}`;
}

/** Validate for saving: non-blank name, ≥1 usable condition, ≥1 action. */
export function validateRule(rule: FilterRule): string | null {
  if (!rule.name.trim()) return "The rule needs a name.";
  if (!rule.conditions.some((c) => c.value.trim())) return "Add at least one condition with a value.";
  if (rule.actions.length === 0) return "Pick at least one action.";
  return null;
}
