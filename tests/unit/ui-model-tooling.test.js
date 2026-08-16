import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  GENERATED_FLOW_PATH,
  GENERATED_TREE_PATH,
  generatedContents,
  loadModel,
  validateModel
} from '../../scripts/ui-model-tools.mjs';

const root = process.cwd();

test('canonical UI model inventory validates with populated Phase 2 content', async () => {
  const { model, schema } = await loadModel(root);
  assert.deepEqual(validateModel(model, schema), []);
  assert.equal(model.model.status, 'ACTIVE');
  assert.equal(model.nodes.length, 46);
  assert.equal(model.interactions.length, 58);
  assert.equal(model.capabilities.length, 22);
  assert.equal(model.feedback.length, 7);
  assert.equal(model.audit.findings.length, 6);
  assert.equal(model.nodes.find((node) => node.id === 'UI-ADMIN-LOGIN-SUBMIT').selectors[0].strategy, 'test_id');
});

test('canonical UI model generates committed Markdown and Mermaid views', async () => {
  const generated = await generatedContents(root);
  assert.equal(await readFile(path.join(root, GENERATED_TREE_PATH), 'utf8'), generated.tree);
  assert.equal(await readFile(path.join(root, GENERATED_FLOW_PATH), 'utf8'), generated.flow);
});

test('canonical UI model rejects broken parent and interaction references', async () => {
  const { model, schema } = await loadModel(root);
  const invalid = structuredClone(model);
  invalid.nodes.push({
    id: 'UI-FOUNDATION',
    type: 'page',
    title: 'Invalid fixture',
    parent: 'UI-MISSING',
    status: 'FOUNDATION',
    roles: [],
    permissions: [],
    entry_conditions: [],
    visible_when: [],
    data_dependencies: [],
    source_files: ['fixture'],
    canonical_references: ['fixture'],
    test_references: ['fixture'],
    live_verified: false
  });
  invalid.interactions.push({
    id: 'INT-FOUNDATION',
    source: 'UI-FOUNDATION',
    trigger: 'fixture',
    control: 'UI-MISSING',
    preconditions: [],
    action: 'navigate',
    success: [],
    failure: [],
    next_state: null,
    side_effects: [],
    messages: [],
    security_boundary: 'fixture',
    capability_ids: [],
    source_files: ['fixture'],
    test_ids: ['fixture']
  });
  assert.match(validateModel(invalid, schema).join('\n'), /missing parent|missing control/);
});

test('canonical UI model requires exactly one complete execution classification per interaction', async () => {
  const { model, schema } = await loadModel(root);
  const missing = structuredClone(model);
  missing.interaction_execution.pop();
  assert.match(validateModel(missing, schema).join('\n'), /has no execution classification/);
  const incomplete = structuredClone(model);
  const entry = incomplete.interaction_execution.find((item) => item.status === 'NOT_EXECUTED');
  delete entry.required_work;
  assert.match(validateModel(incomplete, schema).join('\n'), /requires reason, required_fixture and required_work/);
});

test('canonical UI model rejects invalid traceability targets', async () => {
  const { model, schema } = await loadModel(root);
  const invalid = structuredClone(model);
  invalid.nodes[0].source_files = ['public/missing-ui-source.js'];
  const interaction = invalid.interactions.find((item) => item.verification);
  if (interaction) interaction.verification.evidence = 'test-results/missing-evidence.json';
  const validation = validateModel(invalid, schema).join('\n');
  assert.match(validation, /missing source_files target/);
  if (interaction) assert.match(validation, /invalid evidence target/);
});
