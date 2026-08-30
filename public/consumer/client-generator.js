// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

export const CLIENT_EXAMPLE_FORMATS = Object.freeze([
  Object.freeze({ id: 'curl', label: 'curl' }),
  Object.freeze({ id: 'node', label: 'Node.js' }),
  Object.freeze({ id: 'python', label: 'Python' }),
  Object.freeze({ id: 'powershell', label: 'PowerShell' }),
  Object.freeze({ id: 'n8n', label: 'n8n HTTP Request' })
]);

const DEFAULTS = Object.freeze({
  format: 'curl',
  baseUrl: 'https://<credential-hub>',
  consumerToken: '<consumer-api-token>',
  credentialKey: '<credential-key>',
  secretNames: ['apiKey']
});

const SAFE_IDENTIFIER = /^[A-Za-z][A-Za-z0-9_.-]*$/;

function safeIdentifier(value, fallback) {
  return typeof value === 'string' && (value === `<${fallback}>` || SAFE_IDENTIFIER.test(value)) ? value : `<${fallback}>`;
}

function safeSecretNames(value) {
  const names = Array.isArray(value) ? value : [];
  const safe = [...new Set(names.filter((name) => typeof name === 'string' && SAFE_IDENTIFIER.test(name)))];
  return safe.length > 0 ? safe : [...DEFAULTS.secretNames];
}

function safeBaseUrl(value) {
  if (typeof value !== 'string' || /[\r\n]/.test(value) || !/^https:\/\/[^\s"']+$/.test(value)) return DEFAULTS.baseUrl;
  return value.replace(/\/+$/, '');
}

function normalizeInput(input = {}) {
  const format = CLIENT_EXAMPLE_FORMATS.some(({ id }) => id === input.format) ? input.format : DEFAULTS.format;
  const baseUrl = safeBaseUrl(input.baseUrl ?? DEFAULTS.baseUrl);
  const consumerToken = safeIdentifier(input.consumerToken, 'consumer-api-token');
  const credentialKey = safeIdentifier(input.credentialKey, 'credential-key');
  const secretNames = safeSecretNames(input.secretNames ?? DEFAULTS.secretNames);
  const endpoint = `${baseUrl}/api/v1/consumer/credentials/${credentialKey}/resolve`;
  return { format, baseUrl, consumerToken, credentialKey, secretNames, endpoint };
}

function json(value) {
  return JSON.stringify(value);
}

function curlExample({ endpoint, consumerToken, secretNames }) {
  return [
    'curl --fail --silent --show-error \\',
    `  -X POST "${endpoint}" \\`,
    '  -H "Accept: application/json" \\',
    `  -H "Authorization: Bearer ${consumerToken}" \\`,
    '  -H "Content-Type: application/json" \\',
    `  --data '${json({ secretNames })}'`,
    '',
    '# Use resolved values only for the immediate target operation; do not log or persist them.'
  ].join('\n');
}

function nodeExample({ baseUrl, consumerToken, credentialKey, secretNames }) {
  return `const hubUrl = ${json(baseUrl)};
const consumerToken = ${json(consumerToken)};
const credentialKey = ${json(credentialKey)};
const secretNames = ${json(secretNames)};

const response = await fetch(
  \`${'${hubUrl}'}/api/v1/consumer/credentials/${'${encodeURIComponent(credentialKey)}'}/resolve\`,
  {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      Authorization: \`Bearer ${'${consumerToken}'}\`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ secretNames })
  }
);

if (!response.ok) throw new Error(\`Resolve failed: ${'${response.status}'}\`);
const resolved = await response.json();
const secrets = resolved.data?.secrets;
// Use secrets transiently for the target operation, then release the reference.`;
}

function pythonExample({ endpoint, consumerToken, secretNames }) {
  return `import json
from urllib.request import Request, urlopen

request = Request(
    ${json(endpoint)},
    data=json.dumps({"secretNames": ${json(secretNames)}}).encode("utf-8"),
    headers={
        "Accept": "application/json",
        "Authorization": ${json(`Bearer ${consumerToken}`)},
        "Content-Type": "application/json",
    },
    method="POST",
)

with urlopen(request) as response:
    resolved = json.load(response)
secrets = resolved["data"]["secrets"]
# Use secrets transiently for the target operation; do not log or persist them.`;
}

function powershellExample({ endpoint, consumerToken, secretNames }) {
  return `$headers = @{
  Accept = 'application/json'
  Authorization = ${json(`Bearer ${consumerToken}`)}
}
$body = @{ secretNames = @(${secretNames.map((name) => `'${name}'`).join(', ')}) } | ConvertTo-Json -Compress

$resolved = Invoke-RestMethod \\
  -Method Post \\
  -Uri ${json(endpoint)} \\
  -Headers $headers \\
  -ContentType 'application/json' \\
  -Body $body
$secrets = $resolved.data.secrets
# Use secrets transiently for the target operation; do not log or persist them.`;
}

function n8nExample({ endpoint, consumerToken, secretNames }) {
  return JSON.stringify({
    name: 'Sekalum Resolve',
    type: 'n8n-nodes-base.httpRequest',
    typeVersion: 4.2,
    parameters: {
      method: 'POST',
      url: endpoint,
      sendHeaders: true,
      headerParameters: {
        parameters: [
          { name: 'Accept', value: 'application/json' },
          { name: 'Authorization', value: `Bearer ${consumerToken}` },
          { name: 'Content-Type', value: 'application/json' }
        ]
      },
      sendBody: true,
      contentType: 'raw',
      rawContentType: 'application/json',
      body: JSON.stringify({ secretNames })
    }
  }, null, 2);
}

export function buildClientExample(input = {}) {
  const normalized = normalizeInput(input);
  const examples = {
    curl: curlExample,
    node: nodeExample,
    python: pythonExample,
    powershell: powershellExample,
    n8n: n8nExample
  };
  return examples[normalized.format](normalized);
}

export function listClientExampleFormats() {
  return CLIENT_EXAMPLE_FORMATS.map((format) => ({ ...format }));
}
