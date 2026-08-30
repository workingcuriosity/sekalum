// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

const DAY_MS = 24 * 60 * 60 * 1000;

export const AUDIT_RETENTION_POLICY = Object.freeze({
  type: 'COMBINED',
  retentionDays: 30,
  retentionMs: 30 * DAY_MS,
  maxEvents: 10_000,
  timeBoundary: 'UTC_INSTANT',
  order: 'OLDEST_TO_NEWEST'
});

export function applyAuditRetentionPolicy(entries, { now = new Date(), onMalformed = () => {} } = {}) {
  if (!Array.isArray(entries)) {
    throw new TypeError('Audit entries must be an array');
  }

  const nowMs = toTimestampMs(now, 'now');
  const valid = [];

  for (const [index, entry] of entries.entries()) {
    const timestampMs = toTimestampMs(entry?.timestamp, 'audit timestamp');
    if (timestampMs === null) {
      onMalformed();
      continue;
    }
    valid.push({ entry, index, timestampMs });
  }

  const ageEligible = valid
    .filter(({ timestampMs }) => nowMs - timestampMs < AUDIT_RETENTION_POLICY.retentionMs)
    .sort((left, right) => left.timestampMs - right.timestampMs || left.index - right.index);
  const retained = ageEligible.slice(-AUDIT_RETENTION_POLICY.maxEvents).map(({ entry }) => entry);

  return {
    entries: retained,
    dropped: entries.length - retained.length,
    malformed: entries.length - valid.length
  };
}

function toTimestampMs(value, name) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    if (name === 'now') throw new TypeError('Audit retention clock must be a valid date');
    return null;
  }
  return date.getTime();
}
