import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { loadModel, validateModel } from './ui-model-tools.mjs';

const root = process.cwd();
const { model, schema } = await loadModel(root);
const errors = [...validateModel(model, schema)];
const warnings = [];
const selectorStrategies = new Set(model.taxonomy.selector_strategies ?? []);
const seenExclusive = new Map();
const modeledTestIds = new Set();

function hasStaticSelector(source, selector) {
  const value = selector.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (selector.strategy === 'test_id') return new RegExp(`data-testid=["']${value}["']`).test(source);
  if (selector.strategy === 'id') return new RegExp(`id=["']${value}["']`).test(source);
  if (selector.strategy === 'name') return new RegExp(`name=["']${value}["']`).test(source);
  if (selector.strategy === 'label') return new RegExp(`for=["']${value}["']`).test(source);
  return true;
}

for (const node of model.nodes) {
  const selectors = node.selectors ?? [];
  if (node.test_required && selectors.length === 0) errors.push(`ERROR selector missing for test-required node ${node.id}`);
  for (const selector of selectors) {
    if (!selectorStrategies.has(selector.strategy)) errors.push(`ERROR selector ${node.id} uses unknown strategy ${selector.strategy}`);
    if (!selector.value.trim()) errors.push(`ERROR selector ${node.id} has empty value`);
    const sourcePath = path.join(root, selector.source_file);
    if (!existsSync(sourcePath)) {
      errors.push(`ERROR selector ${node.id} references missing source file ${selector.source_file}`);
      continue;
    }
    const key = `${selector.strategy}:${selector.value}`;
    if (selector.exclusive !== false && seenExclusive.has(key)) errors.push(`ERROR duplicate exclusive selector ${key} on ${seenExclusive.get(key)} and ${node.id}`);
    else seenExclusive.set(key, node.id);
    if (selector.strategy === 'test_id') modeledTestIds.add(selector.value);
    if (!hasStaticSelector(readFileSync(sourcePath, 'utf8'), selector)) {
      const level = selector.runtime_generated ? 'WARNING' : 'ERROR';
      const message = `${level} selector ${key} for ${node.id} not statically found in ${selector.source_file}`;
      if (level === 'ERROR') errors.push(message); else warnings.push(message);
    }
  }
}

const discoveredTestIds = new Map();
for (const file of new Set(model.nodes.flatMap((node) => node.source_files).filter((value) => value.endsWith('.html')))) {
  const absolute = path.join(root, file);
  if (!existsSync(absolute)) continue;
  const source = readFileSync(absolute, 'utf8');
  for (const match of source.matchAll(/data-testid=["']([^"']+)["']/g)) {
    const id = match[1];
    const previous = discoveredTestIds.get(id) ?? [];
    previous.push(file);
    discoveredTestIds.set(id, previous);
  }
}
for (const [id, files] of discoveredTestIds) {
  if (files.length > 1) errors.push(`ERROR duplicate static data-testid ${id} in ${files.join(', ')}`);
  if (!modeledTestIds.has(id)) warnings.push(`WARNING data-testid ${id} is present but not modeled`);
}

for (const node of model.nodes.filter((node) => node.type === 'button' || node.type === 'form' || node.type === 'modal')) {
  if (!node.handler && node.test_required) warnings.push(`WARNING test-required control ${node.id} has no documented handler`);
}

for (const message of errors) console.error(message);
for (const message of warnings) console.warn(message);
console.log(JSON.stringify({ classification: { ERROR: errors.length, WARNING: warnings.length, MANUAL_REVIEW: 0, SKIPPED_WITH_REASON: 0 }, modeled_controls: model.nodes.filter((node) => node.selectors?.length).length }, null, 2));
if (errors.length > 0) process.exitCode = 1;
