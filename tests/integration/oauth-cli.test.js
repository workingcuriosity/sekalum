import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('CLI OAuth command generates Threads authorization URL through framework chain', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'threads'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      THREADS_CLIENT_ID: 'threads-client-id',
      THREADS_CLIENT_SECRET: 'threads-client-secret',
      THREADS_REDIRECT_URI: 'https://credential.example.test/oauth/threads/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: threads/);
  assert.match(result.stdout, /Application container built/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'threads'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'threads'/);
  assert.match(result.stdout, /https:\/\/threads\.net\/oauth\/authorize\?/);
  assert.match(result.stdout, /client_id=/);
  assert.match(result.stdout, /redirect_uri=/);
  assert.match(result.stdout, /scope=threads_basic/);
});


test('CLI OAuth command generates Google authorization URL with default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'google'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
      GOOGLE_REDIRECT_URI: 'https://credential.example.test/oauth/google/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: google/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'google'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'google'/);
  assert.match(result.stdout, /https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
  assert.match(result.stdout, /client_id=google-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Fgoogle%2Fcallback/);
  assert.match(result.stdout, /scope=openid\+email\+profile/);
  assert.match(result.stdout, /access_type=offline/);
  assert.match(result.stdout, /prompt=consent/);
});


test('CLI OAuth command generates Twitch authorization URL with default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'twitch'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      TWITCH_CLIENT_ID: 'twitch-client-id',
      TWITCH_CLIENT_SECRET: 'twitch-client-secret',
      TWITCH_REDIRECT_URI: 'https://credential.example.test/oauth/twitch/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: twitch/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'twitch'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'twitch'/);
  assert.match(result.stdout, /https:\/\/id\.twitch\.tv\/oauth2\/authorize\?/);
  assert.match(result.stdout, /client_id=twitch-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Ftwitch%2Fcallback/);
  assert.match(result.stdout, /scope=user%3Aread%3Aemail/);
});

test('CLI OAuth command generates Kick authorization URL with PKCE and default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'kick'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      KICK_CLIENT_ID: 'kick-client-id',
      KICK_CLIENT_SECRET: 'kick-client-secret',
      KICK_REDIRECT_URI: 'https://credential.example.test/oauth/kick/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: kick/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'kick'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'kick'/);
  assert.match(result.stdout, /https:\/\/id\.kick\.com\/oauth\/authorize\?/);
  assert.match(result.stdout, /client_id=kick-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Fkick%2Fcallback/);
  assert.match(result.stdout, /scope=user%3Aread\+channel%3Aread/);
  assert.match(result.stdout, /code_challenge=/);
  assert.match(result.stdout, /code_challenge_method=S256/);
  assert.match(result.stdout, /state=/);
});


test('CLI OAuth command generates Discord authorization URL with default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'discord'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      DISCORD_CLIENT_ID: 'discord-client-id',
      DISCORD_CLIENT_SECRET: 'discord-client-secret',
      DISCORD_REDIRECT_URI: 'https://credential.example.test/oauth/discord/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: discord/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'discord'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'discord'/);
  assert.match(result.stdout, /https:\/\/discord\.com\/oauth2\/authorize\?/);
  assert.match(result.stdout, /client_id=discord-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Fdiscord%2Fcallback/);
  assert.match(result.stdout, /scope=identify\+email\+guilds/);
  assert.match(result.stdout, /state=/);
});


test('CLI OAuth command generates X authorization URL with PKCE and default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'x'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      X_CLIENT_ID: 'x-client-id',
      X_CLIENT_SECRET: 'x-client-secret',
      X_REDIRECT_URI: 'https://credential.example.test/oauth/x/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: x/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'x'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'x'/);
  assert.match(result.stdout, /https:\/\/twitter\.com\/i\/oauth2\/authorize\?/);
  assert.match(result.stdout, /client_id=x-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Fx%2Fcallback/);
  assert.match(result.stdout, /scope=users\.read\+offline\.access/);
  assert.match(result.stdout, /code_challenge=/);
  assert.match(result.stdout, /code_challenge_method=S256/);
  assert.match(result.stdout, /state=/);
});


test('CLI OAuth command generates Facebook authorization URL with default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'facebook'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      FACEBOOK_CLIENT_ID: 'facebook-client-id',
      FACEBOOK_CLIENT_SECRET: 'facebook-client-secret',
      FACEBOOK_REDIRECT_URI: 'https://credential.example.test/oauth/facebook/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: facebook/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'facebook'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'facebook'/);
  assert.match(result.stdout, /https:\/\/www\.facebook\.com\/v20\.0\/dialog\/oauth\?/);
  assert.match(result.stdout, /client_id=facebook-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Ffacebook%2Fcallback/);
  assert.match(result.stdout, /scope=public_profile%2Cemail/);
  assert.match(result.stdout, /state=/);
});

test('CLI OAuth command generates Instagram authorization URL with default scopes', () => {
  const result = spawnSync(process.execPath, ['src/cli/run-oauth.js', 'instagram'], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      INSTAGRAM_CLIENT_ID: 'instagram-client-id',
      INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
      INSTAGRAM_REDIRECT_URI: 'https://credential.example.test/oauth/instagram/callback'
    }
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Provider registered: instagram/);
  assert.match(result.stdout, /Provider operation 'startOAuth' via provider 'instagram'/);
  assert.match(result.stdout, /Provider operation 'startOAuth' succeeded for 'instagram'/);
  assert.match(result.stdout, /https:\/\/www\.instagram\.com\/oauth\/authorize\?/);
  assert.match(result.stdout, /client_id=instagram-client-id/);
  assert.match(result.stdout, /redirect_uri=https%3A%2F%2Fcredential\.example\.test%2Foauth%2Finstagram%2Fcallback/);
  assert.match(result.stdout, /scope=instagram_business_basic/);
  assert.match(result.stdout, /state=/);
});
