import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { loadModel } from './ui-model-tools.mjs';
import { redactEvidence } from './ui-evidence-tools.mjs';

const RESULT_STATUSES = new Set(['PASSED', 'FAILED', 'SKIPPED', 'BLOCKED', 'NOT_EXECUTED']);
const escapeXml = (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

function normaliseStatus(status) {
  if (status === 'passed') return 'PASSED';
  if (status === 'failed' || status === 'timedOut') return 'FAILED';
  if (status === 'skipped' || status === 'interrupted') return 'SKIPPED';
  return 'NOT_EXECUTED';
}

// Playwright JSON is traversed as its documented suite/spec/test/result structure.
export function collectPlaywrightResults(payload) {
  const results = new Map();
  const visitSuite = (suite) => {
    for (const spec of suite.specs ?? []) {
      for (const entry of spec.tests ?? []) {
        const statuses = (entry.results ?? []).map((result) => normaliseStatus(result.status));
        const status = statuses.includes('FAILED') ? 'FAILED' : statuses.includes('PASSED') ? 'PASSED' : statuses.includes('SKIPPED') ? 'SKIPPED' : 'NOT_EXECUTED';
        results.set(spec.title, { status, results: entry.results ?? [] });
      }
    }
    for (const child of suite.suites ?? []) visitSuite(child);
  };
  for (const suite of payload?.suites ?? []) visitSuite(suite);
  return results;
}

function ratio(covered, total, observed = covered) {
  return total === 0 ? { value: null, covered, total, status: 'NOT_EXECUTED' } : { value: covered / total, covered, total, status: observed === 0 ? 'NOT_EXECUTED' : 'MEASURED' };
}

function regression(current, baseline) {
  if (!baseline?.executable_interactions) return { status: 'REGRESSION_NOT_AVAILABLE' };
  const previous = new Map(baseline.executable_interactions.map((item) => [item.id, item.status]));
  const currentFailures = current.filter((item) => item.status === 'FAILED');
  const previousFailures = [...previous].filter(([, status]) => status === 'FAILED').map(([id]) => id);
  return {
    status: 'REGRESSION_CALCULATED',
    new_failures: currentFailures.filter((item) => previous.get(item.id) !== 'FAILED').map((item) => item.id),
    closed_failures: previousFailures.filter((id) => current.find((item) => item.id === id)?.status === 'PASSED'),
    new_drift: [],
    resolved_drift: []
  };
}

export function createReport(model, playwright, baseline) {
  const observed = collectPlaywrightResults(playwright);
  const executionByInteraction = new Map((model.interaction_execution ?? []).map((entry) => [entry.interaction_id, entry]));
  const executable = model.interactions.filter((item) => executionByInteraction.get(item.id)?.status === 'EXECUTABLE').map((item) => {
    const actual = observed.get(item.verification.test_id);
    return { id: item.id, test_id: item.verification.test_id, capabilities: item.capability_ids, evidence: item.verification.evidence, status: actual?.status ?? 'NOT_EXECUTED', actual_results: actual?.results?.length ?? 0 };
  });
  const executed = executable.filter((item) => item.status !== 'NOT_EXECUTED' && item.status !== 'BLOCKED').length;
  const passed = executable.filter((item) => item.status === 'PASSED').length;
  const status = executable.length === 0 || executed === 0 ? 'NOT_EXECUTED' : executable.some((item) => item.status === 'FAILED') ? 'FAILED' : executable.some((item) => item.status === 'SKIPPED') ? 'SKIPPED' : 'PASSED';
  const classified = Object.fromEntries(['EXECUTABLE', 'BLOCKED', 'NOT_EXECUTED'].map((status) => [status, model.interaction_execution.filter((entry) => entry.status === status).length]));
  return redactEvidence({
    generated_at: new Date().toISOString(), commit: process.env.GITHUB_SHA ?? 'local-uncommitted', status,
    interaction_classification: { modeled: model.interactions.length, ...classified },
    executable_interactions: executable,
    score: {
      interaction_coverage: ratio(executed, executable.length, executed),
      executable_coverage: ratio(passed, executable.length, executed),
      capability_coverage: ratio(new Set(executable.filter((item) => item.status === 'PASSED').flatMap((item) => item.capabilities)).size, model.capabilities.length, executed),
      traceability_coverage: ratio(executable.filter((item) => item.status !== 'NOT_EXECUTED').length, model.interactions.length),
      selector_coverage: { value: null, status: 'NOT_EXECUTED' },
      browser_coverage: ratio(passed, executable.length, executed),
      live_coverage: { value: null, status: 'NOT_EXECUTED' }, ux_coverage: { value: null, status: 'NOT_EXECUTED' }, accessibility_coverage: { value: null, status: 'NOT_EXECUTED' }
    },
    regression: regression(executable, baseline),
    limitations: ['OAuth excluded', 'live evidence requires approved environment']
  });
}

function markdown(report) {
  return `# Executable UI Verification\n\nOverall status: **${report.status}**\n\n| Test | Interaction | Status | Actual results |\n|---|---|---|---:|\n${report.executable_interactions.map((item) => `| ${item.test_id} | ${item.id} | ${item.status} | ${item.actual_results} |`).join('\n')}\n\n## Regression\n\nStatus: **${report.regression.status}**\n\n\`\`\`json\n${JSON.stringify(report.score, null, 2)}\n\`\`\`\n`;
}

function junit(report) {
  const failures = report.executable_interactions.filter((item) => item.status === 'FAILED').length;
  return `<testsuite name="executable-ui" tests="${report.executable_interactions.length}" failures="${failures}">${report.executable_interactions.map((item) => `<testcase name="${escapeXml(item.test_id)}">${item.status === 'FAILED' ? '<failure message="Playwright reported FAILED"/>' : item.status !== 'PASSED' ? `<skipped message="${item.status}"/>` : ''}</testcase>`).join('')}</testsuite>\n`;
}

export async function writeReport(root = process.cwd()) {
  const output = path.resolve(root, process.env.UI_VERIFICATION_OUTPUT ?? 'test-results/ui-verification');
  const resultPath = path.resolve(root, process.env.UI_PLAYWRIGHT_RESULT_PATH ?? 'test-results/ui-smoke.json');
  const baselinePath = process.env.UI_REGRESSION_BASELINE && path.resolve(root, process.env.UI_REGRESSION_BASELINE);
  const { model } = await loadModel(root);
  const playwright = existsSync(resultPath) ? JSON.parse(await readFile(resultPath, 'utf8')) : null;
  const baseline = baselinePath && existsSync(baselinePath) ? JSON.parse(await readFile(baselinePath, 'utf8')) : null;
  const report = createReport(model, playwright, baseline);
  await mkdir(output, { recursive: true });
  await Promise.all([
    writeFile(path.join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`),
    writeFile(path.join(output, 'report.md'), markdown(report)),
    writeFile(path.join(output, 'report.mmd'), `flowchart LR\n${report.executable_interactions.map((item) => `  ${item.id.replaceAll('-', '_')}["${item.id}: ${item.status}"]`).join('\n')}\n`),
    writeFile(path.join(output, 'report.html'), `<html><body><h1>Executable UI Verification: ${report.status}</h1><pre>${JSON.stringify(report, null, 2)}</pre></body></html>\n`),
    writeFile(path.join(output, 'report.junit.xml'), junit(report)),
    writeFile(path.join(output, 'evidence.json'), `${JSON.stringify(report, null, 2)}\n`)
  ]);
  return report;
}

if (process.argv[1] === new URL(import.meta.url).pathname) console.log(JSON.stringify(await writeReport(), null, 2));
