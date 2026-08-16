import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  GENERATED_FLOW_PATH,
  GENERATED_TREE_PATH,
  generatedContents,
  loadModel
} from './ui-model-tools.mjs';

const root = process.cwd();
const { errors, tree, flow } = await generatedContents(root);

if (errors.length > 0) {
  console.error('Canonical UI Interaction Model validation failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log('Canonical UI Interaction Model schema and reference validation passed.');
}

if (process.argv.includes('--check-generated')) {
  const [committedTree, committedFlow] = await Promise.all([
    readFile(path.join(root, GENERATED_TREE_PATH), 'utf8'),
    readFile(path.join(root, GENERATED_FLOW_PATH), 'utf8')
  ]);
  if (committedTree !== tree) {
    console.error(`Generated Markdown is out of date: ${GENERATED_TREE_PATH}`);
    process.exitCode = 1;
  }
  if (committedFlow !== flow) {
    console.error(`Generated Mermaid is out of date: ${GENERATED_FLOW_PATH}`);
    process.exitCode = 1;
  }
  if (committedTree === tree && committedFlow === flow) console.log('Generated UI model views are up to date.');
}

if (process.argv.includes('--summary')) {
  const { model } = await loadModel(root);
  console.log(JSON.stringify({
    nodes: model.nodes.length,
    interactions: model.interactions.length,
    capabilities: model.capabilities.length,
    feedback: model.feedback.length,
    generated: [GENERATED_TREE_PATH, GENERATED_FLOW_PATH]
  }, null, 2));
}
