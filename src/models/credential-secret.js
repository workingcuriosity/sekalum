import crypto from 'node:crypto';
import { validateNamedIdentifier } from '../security/authorization-identifier.js';

export class CredentialSecret {
  constructor({
    id = crypto.randomUUID(),
    name,
    value,
    metadata = {},
    createdAt = new Date(),
    updatedAt = new Date()
  }) {
    if (!id) throw new Error("CredentialSecret: 'id' is required");
    validateNamedIdentifier('secretFieldKey', name);
    if (value === undefined || value === null || value === '') {
      throw new Error("CredentialSecret: 'value' is required");
    }

    this.id = id;
    this.name = name;
    this.value = value;
    this.metadata = Object.freeze({ ...metadata });
    this.createdAt = createdAt instanceof Date ? createdAt : new Date(createdAt);
    this.updatedAt = updatedAt instanceof Date ? updatedAt : new Date(updatedAt);

    Object.freeze(this);
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      value: this.value,
      metadata: this.metadata,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }

  static from(data) {
    if (data instanceof CredentialSecret) return data;
    return new CredentialSecret(data);
  }
}
