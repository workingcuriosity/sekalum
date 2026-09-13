import crypto from 'node:crypto';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';

function required(value, name) {
  const domain = { grantId: 'grantId', consumerId: 'consumerId', credentialId: 'credentialId', credentialGeneration: 'credentialGeneration', providerKey: 'providerKey' }[name] ?? name;
  return validateNamedIdentifier(domain, value);
}

function normalizeSecretNames(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("ConsumerGrant: 'secretNames' must be a non-empty array");
  }

  const names = value.map((name) => validateNamedIdentifier('secretFieldKey', name));
  return Object.freeze([...new Set(names)]);
}

export class ConsumerGrant {
  constructor({
    grantId = crypto.randomUUID(),
    consumerId,
    credentialId,
    credentialGeneration = null,
    providerKey,
    providerProfile = null,
    secretNames,
    createdAt = new Date(),
    updatedAt = new Date()
  } = {}) {
    this.grantId = required(grantId, 'grantId');
    this.consumerId = required(consumerId, 'consumerId');
    this.credentialId = required(credentialId, 'credentialId');
    this.credentialGeneration = credentialGeneration === null || credentialGeneration === undefined
      ? null
      : required(credentialGeneration, 'credentialGeneration');
    this.providerKey = required(providerKey, 'providerKey');
    if (providerProfile?.providerKey !== undefined) validateNamedIdentifier('providerKey', providerProfile.providerKey);
    this.providerProfile = providerProfile ? Object.freeze({ ...providerProfile }) : null;
    this.secretNames = normalizeSecretNames(secretNames);
    this.createdAt = createdAt instanceof Date ? createdAt : new Date(createdAt);
    this.updatedAt = updatedAt instanceof Date ? updatedAt : new Date(updatedAt);

    if (Number.isNaN(this.createdAt.getTime()) || Number.isNaN(this.updatedAt.getTime())) {
      throw new Error('ConsumerGrant: timestamps must be valid dates');
    }

    Object.freeze(this);
  }

  toJSON() {
    return {
      grantId: this.grantId,
      consumerId: this.consumerId,
      credentialId: this.credentialId,
      credentialGeneration: this.credentialGeneration,
      providerKey: this.providerKey,
      ...(this.providerProfile ? { providerProfile: { ...this.providerProfile } } : {}),
      secretNames: [...this.secretNames],
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }

  static from(value) {
    return value instanceof ConsumerGrant ? value : new ConsumerGrant(value);
  }
}
