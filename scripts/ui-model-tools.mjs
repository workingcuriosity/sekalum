import { readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import Ajv2020 from 'ajv/dist/2020.js';

export const MODEL_PATH = 'docs/ui/canonical-ui-interaction-model.yaml';
export const SCHEMA_PATH = 'docs/ui/canonical-ui-interaction-model.schema.json';
export const GENERATED_TREE_PATH = 'docs/ui/generated/ui-tree.md';
export const GENERATED_FLOW_PATH = 'docs/ui/generated/ui-flow.mmd';

export async function loadModel(root = process.cwd()) {
  const [source, schemaText] = await Promise.all([
    readFile(path.join(root, MODEL_PATH), 'utf8'),
    readFile(path.join(root, SCHEMA_PATH), 'utf8')
  ]);

  return {
    model: parse(source),
    schema: JSON.parse(schemaText)
  };
}

function idEntries(model) {
  return [
    ...model.nodes.map((item) => ['node', item.id]),
    ...model.interactions.map((item) => ['interaction', item.id]),
    ...model.capabilities.map((item) => ['capability', item.id]),
    ...model.feedback.map((item) => ['feedback', item.id])
  ];
}

function duplicateIds(model) {
  const seen = new Map();
  const duplicates = [];

  for (const [kind, id] of idEntries(model)) {
    if (seen.has(id)) duplicates.push({ id, kinds: [seen.get(id), kind] });
    else seen.set(id, kind);
  }

  return duplicates;
}

function referenceExists(root, reference) {
  const candidate = path.join(root, reference);
  if (!reference.includes('*')) return existsSync(candidate);
  const directory = path.dirname(candidate);
  const pattern = new RegExp(`^${path.basename(reference).replaceAll('.', '\\.').replaceAll('*', '.*')}$`);
  return existsSync(directory) && readdirSync(directory).some((entry) => pattern.test(entry));
}

function validateFileReferences(errors, root, owner, fields) {
  for (const field of fields) {
    for (const reference of owner[field] ?? []) {
      if (!referenceExists(root, reference)) errors.push(`${owner.id} references missing ${field} target ${reference}`);
    }
  }
}

function validateBackendReference(errors, root, owner, reference) {
  if (!reference) return;
  if (reference.startsWith('src/') || reference.startsWith('public/')) {
    if (!referenceExists(root, reference)) errors.push(`${owner.id} references missing backend source ${reference}`);
    return;
  }
  const routes = reference.split(' and ').map((item) => item.trim());
  const routeSource = existsSync(path.join(root, 'src/oauth/oauth-callback-server.js')) ? readFileSync(path.join(root, 'src/oauth/oauth-callback-server.js'), 'utf8') : '';
  for (const route of routes) if (!routeSource.includes(`'${route}'`)) errors.push(`${owner.id} references missing backend route ${route}`);
}

export function validateModel(model, schema, root = process.cwd()) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validateSchema = ajv.compile(schema);
  const errors = [];

  if (!validateSchema(model)) {
    errors.push(...validateSchema.errors.map((error) => `schema ${error.instancePath || '/'} ${error.message}`));
  }

  if (!model || typeof model !== 'object') return errors;

  for (const duplicate of duplicateIds(model)) {
    errors.push(`duplicate id ${duplicate.id} (${duplicate.kinds.join(', ')})`);
  }

  const nodeIds = new Set(model.nodes?.map((node) => node.id));
  const interactionIds = new Set(model.interactions?.map((interaction) => interaction.id));
  const capabilityIds = new Set(model.capabilities?.map((capability) => capability.id));
  const feedbackIds = new Set(model.feedback?.map((item) => item.id));
  const nodeTypes = new Set(model.taxonomy?.node_types);
  const nodeStatuses = new Set(model.taxonomy?.node_statuses);
  const feedbackTypes = new Set(model.taxonomy?.feedback_types);

  for (const route of model.route_matrix ?? []) {
    if (!nodeIds.has(route.node_id)) errors.push(`route matrix entry ${route.route} references missing node ${route.node_id}`);
  }
  for (const entry of model.api_only_paths ?? []) {
    if (!capabilityIds.has(entry.capability_id)) errors.push(`API-only path ${entry.route} references missing capability ${entry.capability_id}`);
  }
  for (const entry of model.terminal_paths ?? []) {
    if (!nodeIds.has(entry.node_id)) errors.push(`terminal path references missing node ${entry.node_id}`);
  }

  for (const node of model.nodes ?? []) {
    if (!nodeTypes.has(node.type)) errors.push(`node ${node.id} uses unknown type ${node.type}`);
    if (!nodeStatuses.has(node.status)) errors.push(`node ${node.id} uses unknown status ${node.status}`);
    if (node.parent && !nodeIds.has(node.parent)) errors.push(`node ${node.id} references missing parent ${node.parent}`);
    validateFileReferences(errors, root, node, ['source_files', 'canonical_references', 'test_references']);
    validateBackendReference(errors, root, node, node.backend);
  }

  for (const interaction of model.interactions ?? []) {
    if (!nodeIds.has(interaction.source)) errors.push(`interaction ${interaction.id} references missing source ${interaction.source}`);
    if (!nodeIds.has(interaction.control)) errors.push(`interaction ${interaction.id} references missing control ${interaction.control}`);
    if (interaction.next_state && !nodeIds.has(interaction.next_state)) errors.push(`interaction ${interaction.id} references missing next_state ${interaction.next_state}`);
    for (const capabilityId of interaction.capability_ids ?? []) {
      if (!capabilityIds.has(capabilityId)) errors.push(`interaction ${interaction.id} references missing capability ${capabilityId}`);
    }
    for (const messageId of interaction.messages ?? []) {
      if (messageId.startsWith('FB-') && !feedbackIds.has(messageId)) errors.push(`interaction ${interaction.id} references missing feedback ${messageId}`);
    }
    validateFileReferences(errors, root, interaction, ['source_files', 'test_ids']);
    if (interaction.verification) {
      const expectedEvidence = 'test-results/ui-verification/evidence.json';
      if (interaction.verification.evidence !== expectedEvidence || !referenceExists(root, 'scripts/ui-executable-report.mjs')) {
        errors.push(`interaction ${interaction.id} references invalid evidence target ${interaction.verification.evidence}`);
      }
    }
  }

  const executionByInteraction = new Map();
  for (const entry of model.interaction_execution ?? []) {
    if (!interactionIds.has(entry.interaction_id)) errors.push(`execution classification references missing interaction ${entry.interaction_id}`);
    if (executionByInteraction.has(entry.interaction_id)) errors.push(`duplicate execution classification for ${entry.interaction_id}`);
    executionByInteraction.set(entry.interaction_id, entry);
    if (entry.status === 'BLOCKED' && (!entry.reason || !entry.evidence?.length || !entry.blocking_dependency)) errors.push(`blocked interaction ${entry.interaction_id} requires reason, evidence and blocking_dependency`);
    if (entry.status === 'NOT_EXECUTED' && (!entry.reason || !entry.required_fixture || !entry.required_work)) errors.push(`not-executed interaction ${entry.interaction_id} requires reason, required_fixture and required_work`);
  }
  for (const interaction of model.interactions ?? []) {
    const execution = executionByInteraction.get(interaction.id);
    if (!execution) errors.push(`interaction ${interaction.id} has no execution classification`);
    else if (execution.status === 'EXECUTABLE' && !interaction.verification) errors.push(`executable interaction ${interaction.id} requires verification`);
    else if (execution.status !== 'EXECUTABLE' && interaction.verification) errors.push(`non-executable interaction ${interaction.id} must not declare verification`);
  }

  for (const capability of model.capabilities ?? []) {
    validateFileReferences(errors, root, capability, ['source_files', 'canonical_references', 'test_references']);
    for (const route of capability.api_routes ?? []) validateBackendReference(errors, root, capability, route);
  }

  for (const feedback of model.feedback ?? []) {
    if (!feedbackTypes.has(feedback.type)) errors.push(`feedback ${feedback.id} uses unknown type ${feedback.type}`);
    validateFileReferences(errors, root, feedback, ['source_files', 'test_references']);
  }

  return errors;
}

function escapeMermaid(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('"', '\\"').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function mermaidId(id) {
  return id.replaceAll('-', '_');
}

function mermaidLabel(node) {
  return `${escapeMermaid(node.title)}<br/>${escapeMermaid(node.id)}`;
}

function nodePresentation(node) {
  if (node.type === 'application' || node.type === 'area') return 'layout';
  if (['notification', 'empty_state', 'loading_state', 'error_state'].includes(node.type)) return 'feedback';
  if (['modal', 'drawer', 'confirmation'].includes(node.type)) return 'dialog';
  if (['page', 'menu', 'link', 'button', 'wizard'].includes(node.type)) return 'navigation';
  return 'view';
}

function executionByInteraction(model) {
  return new Map((model.interaction_execution ?? []).map((entry) => [entry.interaction_id, entry]));
}

function areaFor(node, byId) {
  let current = node;
  while (current?.parent) {
    const parent = byId.get(current.parent);
    if (parent?.type === 'area') return parent.id;
    current = parent;
  }
  return null;
}

export function renderTree(model) {
  const lines = [
    '<!-- GENERATED FILE. Source: ../canonical-ui-interaction-model.yaml. Do not edit manually. -->',
    '',
    '# Canonical UI Interaction Model — Generated Tree',
    '',
    `Status: \`${model.model.status}\``,
    '',
    `Generated counts: ${model.nodes.length} nodes, ${model.interactions.length} interactions, ${model.capabilities.length} capabilities, ${model.feedback.length} feedback definitions.`,
    ''
  ];

  if (model.nodes.length === 0) {
    lines.push('The canonical YAML source currently contains no Phase 2 UI nodes. This generated view is intentionally an empty foundation and is not a coverage report.');
    return `${lines.join('\n')}\n`;
  }

  const children = new Map();
  for (const node of model.nodes) {
    const parent = node.parent ?? null;
    const list = children.get(parent) ?? [];
    list.push(node);
    children.set(parent, list);
  }

  const visit = (parent, depth) => {
    for (const node of children.get(parent) ?? []) {
      lines.push(`${'  '.repeat(depth)}- **${node.title}** \`${node.id}\` (${node.type}, ${node.status})`);
      visit(node.id, depth + 1);
    }
  };

  visit(null, 0);

  lines.push('');
  lines.push('## Route Matrix');
  lines.push('');
  lines.push('| Route | UI node | Role | Authentication | Navigation entry | Terminal |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const route of model.route_matrix ?? []) {
    lines.push(`| \`${route.route}\` | \`${route.node_id}\` | ${route.role} | ${route.authentication} | ${route.navigation_entry} | ${route.terminal ? 'yes' : 'no'} |`);
  }

  lines.push('');
  lines.push('## API-only Paths');
  lines.push('');
  lines.push('| Route | Capability | Owner | Reason |');
  lines.push('| --- | --- | --- | --- |');
  for (const entry of model.api_only_paths ?? []) {
    lines.push(`| \`${entry.route}\` | \`${entry.capability_id}\` | ${entry.owner} | ${entry.reason} |`);
  }

  lines.push('');
  lines.push('## Terminal UI Paths');
  lines.push('');
  lines.push('| UI node | Condition | Result |');
  lines.push('| --- | --- | --- |');
  for (const entry of model.terminal_paths ?? []) {
    lines.push(`| \`${entry.node_id}\` | ${entry.condition} | ${entry.result} |`);
  }
  return `${lines.join('\n')}\n`;
}

export function renderFlow(model) {
  const lines = [
    '%% GENERATED FILE. Source: ../canonical-ui-interaction-model.yaml. Do not edit manually.',
    '%% Human-readable UI hierarchy. Parent-child edges are solid; executable local interactions are dashed.',
    'flowchart TB'
  ];

  if (model.nodes.length === 0) {
    lines.push('  FOUNDATION["Canonical UI Interaction Model Foundation"]');
    return `${lines.join('\n')}\n`;
  }

  const byId = new Map(model.nodes.map((node) => [node.id, node]));
  const children = new Map();
  for (const node of model.nodes) {
    const list = children.get(node.parent ?? null) ?? [];
    list.push(node);
    children.set(node.parent ?? null, list);
  }

  const renderNode = (node, indent) => {
    lines.push(`${' '.repeat(indent)}${mermaidId(node.id)}["${mermaidLabel(node)}"]`);
  };

  const renderBranch = (node, indent) => {
    const descendants = children.get(node.id) ?? [];
    if (descendants.length === 0) {
      renderNode(node, indent);
      return;
    }

    const groupId = `${mermaidId(node.id)}_GROUP`;
    lines.push(`${' '.repeat(indent)}subgraph ${groupId}["${escapeMermaid(node.title)}"]`);
    lines.push(`${' '.repeat(indent + 2)}direction TB`);
    renderNode(node, indent + 2);
    for (const child of descendants) renderBranch(child, indent + 2);
    for (const child of descendants) lines.push(`${' '.repeat(indent + 2)}${mermaidId(node.id)} --> ${mermaidId(child.id)}`);
    for (let index = 1; index < descendants.length; index += 1) {
      lines.push(`${' '.repeat(indent + 2)}${mermaidId(descendants[index - 1].id)} ~~~ ${mermaidId(descendants[index].id)}`);
    }
    lines.push(`${' '.repeat(indent)}end`);
  };

  const root = model.nodes.find((node) => !node.parent && node.type === 'application') ?? model.nodes.find((node) => !node.parent);
  renderNode(root, 2);
  const rootChildren = children.get(root.id) ?? [];
  lines.push('  subgraph UI_AREAS["Sekalum UI Areas"]');
  lines.push('    direction LR');
  for (const child of rootChildren) renderBranch(child, 4);
  lines.push('  end');
  for (const child of rootChildren) lines.push(`  ${mermaidId(root.id)} --> ${mermaidId(child.id)}`);

  lines.push('  subgraph ROUTE_MATRIX["Canonical route matrix"]');
  lines.push('    direction LR');
  for (const route of model.route_matrix ?? []) {
    const source = route.navigation_entry.toLowerCase().includes('handoff') ? 'UI_CONSUMER_HANDOFF' : 'UI_ADMIN_NAV';
    lines.push(`    ${source} -.->|${escapeMermaid(route.route)}| ${mermaidId(route.node_id)}`);
  }
  lines.push('  end');

  const execution = executionByInteraction(model);
  for (const interaction of model.interactions) {
    const classification = execution.get(interaction.id);
    if (classification?.status !== 'EXECUTABLE' || !interaction.next_state) continue;
    const source = byId.get(interaction.source);
    const target = byId.get(interaction.next_state);
    if (!source || !target || areaFor(source, byId) !== areaFor(target, byId)) continue;
    lines.push(`  ${mermaidId(source.id)} -.->|${escapeMermaid(interaction.id)}| ${mermaidId(target.id)}`);
  }

  const counts = ['BLOCKED', 'NOT_EXECUTED'].map((status) => ({
    status,
    count: [...execution.values()].filter((entry) => entry.status === status).length
  }));
  lines.push('  subgraph EXECUTION_CLASSIFICATIONS["Interaction execution classifications — outside the UI hierarchy"]');
  lines.push('    direction LR');
  for (const { status, count } of counts) {
    lines.push(`    EXECUTION_${status}["${status}<br/>${count} interaction${count === 1 ? '' : 's'}"]`);
  }
  lines.push('  end');

  lines.push('  subgraph LEGEND["Legend"]');
  lines.push('    direction LR');
  lines.push('    LEGEND_LAYOUT["Layout / shell"]');
  lines.push('    LEGEND_NAVIGATION["Navigation / entry"]');
  lines.push('    LEGEND_VIEW["Screen / view"]');
  lines.push('    LEGEND_DIALOG["Dialog / confirmation"]');
  lines.push('    LEGEND_FEEDBACK["Feedback / status"]');
  lines.push('    LEGEND_BLOCKED["BLOCKED"]');
  lines.push('    LEGEND_NOT_EXECUTED["NOT_EXECUTED"]');
  lines.push('  end');

  for (const node of model.nodes) lines.push(`  class ${mermaidId(node.id)} ${nodePresentation(node)}`);
  lines.push('  class EXECUTION_BLOCKED,LEGEND_BLOCKED blocked');
  lines.push('  class EXECUTION_NOT_EXECUTED,LEGEND_NOT_EXECUTED notExecuted');
  lines.push('  class LEGEND_LAYOUT layout');
  lines.push('  class LEGEND_NAVIGATION navigation');
  lines.push('  class LEGEND_VIEW view');
  lines.push('  class LEGEND_DIALOG dialog');
  lines.push('  class LEGEND_FEEDBACK feedback');
  lines.push('  classDef layout fill:#f3edff,stroke:#8b6bd6,color:#241447,stroke-width:2px');
  lines.push('  classDef navigation fill:#edf6ff,stroke:#4e8fc8,color:#12395d,stroke-width:1.5px');
  lines.push('  classDef view fill:#edf9ee,stroke:#69a66d,color:#1d4d22,stroke-width:1.5px');
  lines.push('  classDef dialog fill:#f3fbf2,stroke:#69a66d,color:#1d4d22,stroke-dasharray: 5 3');
  lines.push('  classDef feedback fill:#fff7e8,stroke:#d09133,color:#654008,stroke-width:1.5px');
  lines.push('  classDef blocked fill:#fff0f0,stroke:#c04a4a,color:#6b1515,stroke-width:2px,stroke-dasharray: 6 3');
  lines.push('  classDef notExecuted fill:#f5f5f5,stroke:#777,color:#333,stroke-dasharray: 4 3');
  lines.push('  style UI_AREAS fill:#ffffff,stroke:#cccccc,stroke-width:1px');
  for (const area of rootChildren) {
    lines.push(`  style ${mermaidId(area.id)}_GROUP fill:${area.id === 'UI-ADMIN' ? '#f8fbff' : '#fffaf0'},stroke:${area.id === 'UI-ADMIN' ? '#85b3dd' : '#e7b45c'},stroke-width:1.5px`);
  }
  lines.push('  style EXECUTION_CLASSIFICATIONS fill:#fafafa,stroke:#999,stroke-dasharray: 4 3');
  lines.push('  style LEGEND fill:#ffffff,stroke:#bbbbbb,stroke-width:1px');
  return `${lines.join('\n')}\n`;
}

export async function generatedContents(root = process.cwd()) {
  const { model, schema } = await loadModel(root);
  return {
    errors: validateModel(model, schema),
    tree: renderTree(model),
    flow: renderFlow(model)
  };
}

export async function writeGenerated(root = process.cwd()) {
  const generated = await generatedContents(root);
  await writeFile(path.join(root, GENERATED_TREE_PATH), generated.tree);
  await writeFile(path.join(root, GENERATED_FLOW_PATH), generated.flow);
  return generated;
}
