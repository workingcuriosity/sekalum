const SENSITIVE_KEY = /authorization|cookie|session|token|secret|api[-_]?key|password|access[-_]?token|refresh[-_]?token/i;
const BEARER = /\bBearer\s+[^\s"']+/gi;
const ASSIGNMENT = /\b(access[_-]?token|refresh[_-]?token|api[_-]?key|secret|password)\s*[:=]\s*[^\s,}"']+/gi;

export function redactEvidence(value, key = '') {
  if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((item) => redactEvidence(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactEvidence(item, name)]));
  if (typeof value !== 'string') return value;
  return value.replace(BEARER, 'Bearer [REDACTED]').replace(ASSIGNMENT, '$1=[REDACTED]');
}

export function evidenceRecord({ test_id, result, details = {}, limitations = [] }) {
  return redactEvidence({ environment: 'local-ui-fixture', verified_at: new Date().toISOString(), commit: process.env.GITHUB_SHA ?? 'local-uncommitted', test_id, result, evidence_reference: 'test-results/ui-evidence.json', limitations, details });
}
