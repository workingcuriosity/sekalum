import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

function runProviders(args) {
  return spawnSync(process.execPath, ['src/cli/run-providers.js', ...args], {
    encoding: 'utf8',
    timeout: 10000,
  });
}

function parseOutput(result) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const jsonStart = output.lastIndexOf('\n{');

  if (jsonStart >= 0) {
    return JSON.parse(output.slice(jsonStart + 1));
  }

  return JSON.parse(output);
}

test('CLI providers list returns registered providers', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.ok(Array.isArray(response.data));
  const threads = response.data.find((provider) => provider.key === 'threads');
  assert.ok(threads);
  assert.equal(threads.displayName, 'Threads');
  assert.equal(threads.description, 'Meta Threads OAuth provider');
});

test('CLI providers get returns provider metadata', () => {
  const result = runProviders(['get', 'threads']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.equal(response.data.key, 'threads');
  assert.equal(response.data.displayName, 'Threads');
  assert.equal(response.data.description, 'Meta Threads OAuth provider');
});

test('CLI providers capabilities returns provider capabilities', () => {
  const result = runProviders(['capabilities', 'threads']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  assert.ok(Array.isArray(response.data));
});

test('CLI providers get returns NOT_FOUND for unknown provider', () => {
  const result = runProviders(['get', 'unknown-provider']);

  assert.equal(result.status, 1, result.stdout || result.stderr);

  const response = parseOutput(result);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'NOT_FOUND');
});


test('CLI providers list includes Google provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const google = response.data.find((provider) => provider.key === 'google');
  assert.ok(google);
  assert.equal(google.displayName, 'Google OAuth2');
  assert.equal(google.description, 'Google OAuth2 provider for Google account credentials');
});

test('CLI providers list includes Twitch provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const twitch = response.data.find((provider) => provider.key === 'twitch');
  assert.ok(twitch);
  assert.equal(twitch.displayName, 'Twitch OAuth2');
  assert.equal(twitch.description, 'Twitch OAuth2 provider for Helix API credentials');
});

test('CLI providers list includes Kick provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const kick = response.data.find((provider) => provider.key === 'kick');
  assert.ok(kick);
  assert.equal(kick.displayName, 'Kick OAuth2.1');
  assert.equal(kick.description, 'Kick OAuth 2.1 provider with PKCE for Kick Public API credentials');
});


test('CLI providers list includes Discord provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const discord = response.data.find((provider) => provider.key === 'discord');
  assert.ok(discord);
  assert.equal(discord.displayName, 'Discord OAuth2');
  assert.equal(discord.description, 'Discord OAuth2 user provider for Discord API credentials');
});


test('CLI providers list includes X provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const x = response.data.find((provider) => provider.key === 'x');
  assert.ok(x);
  assert.equal(x.displayName, 'X OAuth2');
  assert.equal(x.description, 'X OAuth2 user provider with PKCE for X API credentials');
});


test('CLI providers list includes Facebook provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const facebook = response.data.find((provider) => provider.key === 'facebook');
  assert.ok(facebook);
  assert.equal(facebook.displayName, 'Facebook OAuth2');
  assert.equal(facebook.description, 'Facebook OAuth2 provider for Facebook Graph API credentials');
});

test('CLI providers list includes Instagram provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const instagram = response.data.find((provider) => provider.key === 'instagram');
  assert.ok(instagram);
  assert.equal(instagram.displayName, 'Instagram OAuth2');
  assert.equal(instagram.description, 'Instagram OAuth2 provider for Instagram API credentials');
});


test('CLI providers list includes SFTP provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const sftp = response.data.find((provider) => provider.key === 'sftp');
  assert.ok(sftp);
  assert.equal(sftp.displayName, 'SFTP Credentials');
  assert.equal(sftp.description, 'SFTP username/password provider for secure file transfer credentials');
});


test('CLI providers list includes FTP provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const ftp = response.data.find((provider) => provider.key === 'ftp');
  assert.ok(ftp);
  assert.equal(ftp.displayName, 'FTP Credentials');
  assert.equal(ftp.description, 'FTP username/password provider for file transfer credentials');
});

test('CLI providers list includes OpenAI provider', () => {
  const result = runProviders(['list']);

  assert.equal(result.status, 0, result.stderr || result.stdout);

  const response = parseOutput(result);
  assert.equal(response.success, true);
  const openai = response.data.find((provider) => provider.key === 'openai');
  assert.ok(openai);
  assert.equal(openai.displayName, 'OpenAI API Key');
  assert.equal(openai.description, 'OpenAI API-key provider for OpenAI and ChatGPT API credentials');
});
