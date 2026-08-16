import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { loadModel } from '../../scripts/ui-model-tools.mjs';
import { createReport, writeReport } from '../../scripts/ui-executable-report.mjs';

const root = process.cwd();

test('verification report marks absent browser execution as NOT_EXECUTED and regression unavailable', async () => {
  const { model } = await loadModel(root);
  const report = createReport(model, null, null);
  assert.equal(report.status, 'NOT_EXECUTED');
  assert.equal(report.regression.status, 'REGRESSION_NOT_AVAILABLE');
  assert.deepEqual(report.interaction_classification, { modeled: 58, EXECUTABLE: 21, BLOCKED: 1, NOT_EXECUTED: 36 });
  assert.ok(report.executable_interactions.every((item) => item.status === 'NOT_EXECUTED'));
});

test('verification report derives failures from structured Playwright results', async () => {
  const { model } = await loadModel(root);
  const testId = model.interactions.find((item) => item.verification).verification.test_id;
  const report = createReport(model, { suites: [{ specs: [{ title: testId, tests: [{ results: [{ status: 'failed' }] }] }] }] }, null);
  assert.equal(report.status, 'FAILED');
  assert.equal(report.executable_interactions.find((item) => item.test_id === testId).status, 'FAILED');
});

test('written JUnit faithfully represents non-executed browser results', async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'credential-hub-ui-report-'));
  const oldOutput = process.env.UI_VERIFICATION_OUTPUT;
  const oldResult = process.env.UI_PLAYWRIGHT_RESULT_PATH;
  try {
    process.env.UI_VERIFICATION_OUTPUT = temporary;
    process.env.UI_PLAYWRIGHT_RESULT_PATH = path.join(temporary, 'missing.json');
    await writeReport(root);
    const xml = await readFile(path.join(temporary, 'report.junit.xml'), 'utf8');
    assert.match(xml, /<skipped message="NOT_EXECUTED"\/>/);
    assert.match(xml, /failures="0"/);
  } finally {
    if (oldOutput === undefined) delete process.env.UI_VERIFICATION_OUTPUT; else process.env.UI_VERIFICATION_OUTPUT = oldOutput;
    if (oldResult === undefined) delete process.env.UI_PLAYWRIGHT_RESULT_PATH; else process.env.UI_PLAYWRIGHT_RESULT_PATH = oldResult;
    await rm(temporary, { recursive: true, force: true });
  }
});
