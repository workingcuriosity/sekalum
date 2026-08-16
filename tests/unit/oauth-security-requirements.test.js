import test from 'node:test';
import assert from 'node:assert/strict';

import {
  OAuthSecurityRequirement,
  OAuthSecurityRequirements
} from '../../src/models/oauth-security-requirements.js';

test('OAuthSecurityRequirements defaults to required state and disabled PKCE/nonce', () => {
  const requirements = OAuthSecurityRequirements.default();

  assert.equal(requirements.state, OAuthSecurityRequirement.REQUIRED);
  assert.equal(requirements.pkce, OAuthSecurityRequirement.DISABLED);
  assert.equal(requirements.nonce, OAuthSecurityRequirement.DISABLED);
  assert.equal(requirements.requiresState(), true);
  assert.equal(requirements.requiresPkce(), false);
});

test('OAuthSecurityRequirements accepts provider contract values', () => {
  const requirements = new OAuthSecurityRequirements({
    state: 'required',
    pkce: 'required',
    nonce: 'optional'
  });

  assert.equal(requirements.requiresState(), true);
  assert.equal(requirements.requiresPkce(), true);
  assert.equal(requirements.supportsPkce(), true);
  assert.deepEqual(requirements.toJSON(), {
    state: 'required',
    pkce: 'required',
    nonce: 'optional'
  });
});

test('OAuthSecurityRequirements rejects unknown values', () => {
  assert.throws(
    () => new OAuthSecurityRequirements({ pkce: 'sometimes' }),
    /pkce must be one of required, optional, disabled/
  );
});
