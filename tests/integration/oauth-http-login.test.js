import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

function waitForOutput(child, pattern, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for ${pattern}. Output so far:\n${output}`));
    }, timeoutMs);

    const onData = (chunk) => {
      output += chunk.toString();
      if (pattern.test(output)) {
        clearTimeout(timer);
        resolve(output);
      }
    };

    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Process exited with code ${code}. Output:\n${output}`));
    });
  });
}

test('HTTP OAuth login endpoint redirects to Threads OAuth URL with state', async () => {
  const port = 3101;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      THREADS_CLIENT_ID: 'threads-client-id',
      THREADS_CLIENT_SECRET: 'threads-client-secret',
      THREADS_REDIRECT_URI: 'https://credential.example.test/oauth/threads/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/threads/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/threads\.net\/oauth\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'threads.net');
    assert.equal(parsed.pathname, '/oauth/authorize');
    assert.equal(parsed.searchParams.get('scope'), 'threads_basic');
    assert.ok(parsed.searchParams.get('client_id'));
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
  } finally {
    child.kill('SIGTERM');
  }
});

test('HTTP OAuth login endpoint redirects to Twitch OAuth URL with state', async () => {
  const port = 3102;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      TWITCH_CLIENT_ID: 'twitch-client-id',
      TWITCH_CLIENT_SECRET: 'twitch-client-secret',
      TWITCH_REDIRECT_URI: 'https://credential.example.test/oauth/twitch/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/twitch/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/id\.twitch\.tv\/oauth2\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'id.twitch.tv');
    assert.equal(parsed.pathname, '/oauth2/authorize');
    assert.equal(parsed.searchParams.get('client_id'), 'twitch-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'user:read:email');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
  } finally {
    child.kill('SIGTERM');
  }
});

test('HTTP OAuth login endpoint redirects to Kick OAuth URL with state and PKCE', async () => {
  const port = 3103;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      KICK_CLIENT_ID: 'kick-client-id',
      KICK_CLIENT_SECRET: 'kick-client-secret',
      KICK_REDIRECT_URI: 'https://credential.example.test/oauth/kick/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/kick/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/id\.kick\.com\/oauth\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'id.kick.com');
    assert.equal(parsed.pathname, '/oauth/authorize');
    assert.equal(parsed.searchParams.get('client_id'), 'kick-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'user:read channel:read');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
    assert.ok(parsed.searchParams.get('code_challenge'));
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  } finally {
    child.kill('SIGTERM');
  }
});


test('HTTP OAuth login endpoint redirects to Discord OAuth URL with state', async () => {
  const port = 3104;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      DISCORD_CLIENT_ID: 'discord-client-id',
      DISCORD_CLIENT_SECRET: 'discord-client-secret',
      DISCORD_REDIRECT_URI: 'https://credential.example.test/oauth/discord/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/discord/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/discord\.com\/oauth2\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'discord.com');
    assert.equal(parsed.pathname, '/oauth2/authorize');
    assert.equal(parsed.searchParams.get('client_id'), 'discord-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'identify email guilds');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
  } finally {
    child.kill('SIGTERM');
  }
});


test('HTTP OAuth login endpoint redirects to X OAuth URL with state and PKCE', async () => {
  const port = 3105;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      X_CLIENT_ID: 'x-client-id',
      X_CLIENT_SECRET: 'x-client-secret',
      X_REDIRECT_URI: 'https://credential.example.test/oauth/x/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/x/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/twitter\.com\/i\/oauth2\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'twitter.com');
    assert.equal(parsed.pathname, '/i/oauth2/authorize');
    assert.equal(parsed.searchParams.get('client_id'), 'x-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'users.read offline.access');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
    assert.ok(parsed.searchParams.get('code_challenge'));
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  } finally {
    child.kill('SIGTERM');
  }
});


test('HTTP OAuth login endpoint redirects to Facebook OAuth URL with state', async () => {
  const port = 3106;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      FACEBOOK_CLIENT_ID: 'facebook-client-id',
      FACEBOOK_CLIENT_SECRET: 'facebook-client-secret',
      FACEBOOK_REDIRECT_URI: 'https://credential.example.test/oauth/facebook/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/facebook/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/www\.facebook\.com\/v20\.0\/dialog\/oauth\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'www.facebook.com');
    assert.equal(parsed.pathname, '/v20.0/dialog/oauth');
    assert.equal(parsed.searchParams.get('client_id'), 'facebook-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'public_profile,email');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
  } finally {
    child.kill('SIGTERM');
  }
});

test('HTTP OAuth login endpoint redirects to Instagram OAuth URL with state', async () => {
  const port = 3107;
  const child = spawn(process.execPath, ['src/index.js'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      INSTAGRAM_CLIENT_ID: 'instagram-client-id',
      INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
      INSTAGRAM_REDIRECT_URI: 'https://credential.example.test/oauth/instagram/callback',
      OAUTH_CALLBACK_PORT: String(port)
    }
  });

  try {
    await waitForOutput(child, /Application started/);

    const response = await fetch(`http://127.0.0.1:${port}/oauth/instagram/login`, {
      redirect: 'manual',
    });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location, 'Location header missing');
    assert.match(location, /^https:\/\/www\.instagram\.com\/oauth\/authorize\?/);

    const parsed = new URL(location);
    assert.equal(parsed.hostname, 'www.instagram.com');
    assert.equal(parsed.pathname, '/oauth/authorize');
    assert.equal(parsed.searchParams.get('client_id'), 'instagram-client-id');
    assert.equal(parsed.searchParams.get('scope'), 'instagram_business_basic');
    assert.ok(parsed.searchParams.get('redirect_uri'));
    assert.ok(parsed.searchParams.get('state'));
  } finally {
    child.kill('SIGTERM');
  }
});
