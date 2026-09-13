import crypto from 'node:crypto';

import { SerializedMutationQueue } from '../storage/serialized-mutation-queue.js';
import { withBindingCommitLock } from '../storage/binding-commit-coordinator.js';
import { validateNamedIdentifier, AuthorizationIdentifierError } from '../security/authorization-identifier.js';

const BOOTSTRAP_SECRET_MIN_BYTES = 32;
const BOOTSTRAP_SECRET_MIN_DISTINCT_BYTES = 8;
const BOOTSTRAP_SECRET_MIN_ENTROPY_BITS_PER_BYTE = 3.5;
const BOOTSTRAP_SECRET_MAX_REPEATED_PATTERN_BYTES = 16;
const BOOTSTRAP_SECRET_MIN_MONOTONIC_RUN = 8;
const KNOWN_BOOTSTRAP_PLACEHOLDERS = new Set([
  'REPLACE_WITH_A_UNIQUE_HIGH_ENTROPY_BOOTSTRAP_TOKEN',
  'YOUR_HIGH_ENTROPY_BOOTSTRAP_TOKEN'
]);

const DEFAULT_ROLES = Object.freeze([
  {
    roleKey: 'admin',
    displayName: 'Administrator',
    description: 'Vollzugriff auf Sekalum Verwaltung und Betriebsfunktionen.',
    permissions: ['credentials:manage', 'credentials:read', 'credentials:consume', 'consumer-grants:manage', 'providers:manage', 'providers:read', 'scheduler:manage', 'scheduler:read', 'management:read', 'users:manage', 'users:read', 'audit:read', 'export:read', 'backup:manage', 'backup:read', 'metrics:read', 'api-tokens:manage', 'api-tokens:read']
  },
  {
    roleKey: 'operator',
    displayName: 'Operator',
    description: 'Operative Verwaltung von Credentials, Providern und Scheduler-Aktionen.',
    permissions: ['credentials:manage', 'credentials:read', 'providers:read', 'scheduler:manage', 'scheduler:read', 'management:read', 'users:read', 'metrics:read', 'api-tokens:read']
  },
  {
    roleKey: 'viewer',
    displayName: 'Viewer',
    description: 'Lesender Zugriff auf Status, Dashboard und Management-Ansichten.',
    permissions: ['credentials:read', 'providers:read', 'scheduler:read', 'management:read', 'users:read', 'metrics:read', 'api-tokens:read']
  }
]);

function hasRepeatedPattern(bytes) {
  const maxPeriod = Math.min(BOOTSTRAP_SECRET_MAX_REPEATED_PATTERN_BYTES, Math.floor(bytes.length / 2));
  for (let period = 1; period <= maxPeriod; period += 1) {
    let repeated = true;
    for (let index = period; index < bytes.length; index += 1) {
      if (bytes[index] !== bytes[index % period]) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }
  return false;
}

function hasMonotonicRun(bytes) {
  let previousDelta = null;
  let runLength = 1;
  for (let index = 1; index < bytes.length; index += 1) {
    const delta = bytes[index] - bytes[index - 1];
    if ((delta === 1 || delta === -1) && delta === previousDelta) {
      runLength += 1;
    } else {
      runLength = 2;
    }
    previousDelta = delta;
    if (runLength >= BOOTSTRAP_SECRET_MIN_MONOTONIC_RUN) return true;
  }
  return false;
}

function meetsBootstrapEntropyRequirement(value) {
  const bytes = Buffer.from(value, 'utf8');
  if (new Set(bytes).size < BOOTSTRAP_SECRET_MIN_DISTINCT_BYTES) return false;
  if (hasRepeatedPattern(bytes) || hasMonotonicRun(bytes)) return false;

  const frequencies = new Map();
  for (const byte of bytes) frequencies.set(byte, (frequencies.get(byte) ?? 0) + 1);
  const entropy = [...frequencies.values()].reduce((sum, count) => {
    const probability = count / bytes.length;
    return sum - (probability * Math.log2(probability));
  }, 0);
  return entropy >= BOOTSTRAP_SECRET_MIN_ENTROPY_BITS_PER_BYTE;
}

export class AccessManagementService {
  constructor({ store = null, auditLogService = null, config = null, bootstrapSecret = undefined, apiTokenService = null } = {}) {
    this.store = store;
    this.auditLogService = auditLogService;
    const configuredBootstrapSecret = bootstrapSecret === undefined
      ? config?.get?.('ADMIN_BOOTSTRAP_TOKEN', null)
      : bootstrapSecret;
    this.bootstrapSecret = this.#normalizeBootstrapSecret(configuredBootstrapSecret);
    this.apiTokenService = apiTokenService;
    this.roles = DEFAULT_ROLES.map((role) => ({ ...role, permissions: [...role.permissions] }));
    this.users = [];
    this.principalTombstones = [];
    this.bootstrapCompleted = false;
    this.mutationQueue = new SerializedMutationQueue();
  }

  async listRoles() {
    return this.roles.map((role) => this.#roleItem(role));
  }

  async listUsers() {
    const records = await this.#loadUsers();
    return records.map((user) => this.#userItem(user));
  }

  async getRestoreState() {
    const [users, principalTombstones] = await Promise.all([
      this.#loadUsers(),
      this.#loadPrincipalTombstones()
    ]);
    return {
      users: users.map((user) => ({ ...user })),
      roles: await this.listRoles(),
      principalTombstones: principalTombstones.map((tombstone) => ({ ...tombstone }))
    };
  }

  async getRestoreSnapshot() {
    const state = await this.getRestoreState();
    return {
      users: state.users.map((user) => ({ ...user })),
      roles: state.roles.map((role) => ({ ...role, permissions: [...role.permissions] })),
      principalTombstones: state.principalTombstones.map((tombstone) => ({ ...tombstone })),
      bootstrapCompleted: this.bootstrapCompleted
    };
  }

  async restoreSnapshot(snapshot = {}) {
    return withBindingCommitLock(() => this.mutationQueue.run(async () => {
      await this.#savePrincipalTombstones(snapshot.principalTombstones ?? []);
      await this.#saveUsers(snapshot.users ?? [], {
        bootstrapCompleted: snapshot.bootstrapCompleted === true || (snapshot.users ?? []).length > 0
      });
      return (snapshot.users ?? []).map((user) => this.#userItem(user));
    }));
  }

  async isDeletedIdentity(userId) {
    return (await this.#loadPrincipalTombstones()).some((tombstone) => tombstone.userId === userId);
  }

  async createUser(input = {}) {
    return withBindingCommitLock(() => this.mutationQueue.run(() => this.#createUser(input)));
  }

  async bootstrapFirstAdministrator(input = {}, proof = null) {
    return withBindingCommitLock(() => this.mutationQueue.run(() => this.#bootstrapFirstAdministrator(input, proof)));
  }

  async #bootstrapFirstAdministrator(input = {}, proof = null) {
    const users = await this.#loadUsers();

    if (this.bootstrapCompleted || users.length > 0) {
      throw this.#bootstrapClosed();
    }

    if (!this.bootstrapSecret) {
      throw this.#bootstrapUnavailable();
    }

    if (!this.#timingSafeSecretMatch(proof)) {
      throw this.#bootstrapProofInvalid();
    }

    const user = this.#normalizeFirstAdministratorInput(input);
    const tombstones = await this.#loadPrincipalTombstones();
    this.#assertPrincipalIdentityAvailable(user.userId, tombstones);
    const now = new Date().toISOString();
    const record = {
      ...user,
      principalGeneration: crypto.randomUUID(),
      createdAt: now,
      updatedAt: now
    };

    await this.#saveUsers([record], { bootstrapCompleted: true });
    await this.#audit({
      action: 'user.created',
      targetId: record.userId,
      result: 'success',
      actorUserId: null,
      details: { roleKey: record.roleKey, status: record.status, bootstrap: true }
    });
    return this.#userItem(record);
  }

  async #createUser(input = {}) {
    const user = this.#normalizeUserInput(input);
    const users = await this.#loadUsers();
    const tombstones = await this.#loadPrincipalTombstones();

    if (users.some((item) => item.userId === user.userId)) {
      throw this.#badRequest(`User '${user.userId}' already exists`);
    }

    this.#assertPrincipalIdentityAvailable(user.userId, tombstones);

    this.#assertKnownRole(user.roleKey);

    const now = new Date().toISOString();
    const record = {
      ...user,
      principalGeneration: crypto.randomUUID(),
      status: user.status ?? 'active',
      createdAt: now,
      updatedAt: now
    };

    users.push(record);
    await this.#saveUsers(users, { bootstrapCompleted: true });
    await this.#audit({
      action: 'user.created',
      targetId: record.userId,
      result: 'success',
      actorUserId: input.actorUserId,
      details: { roleKey: record.roleKey, status: record.status }
    });
    return this.#userItem(record);
  }

  async updateUser(userId, input = {}) {
    return withBindingCommitLock(() => this.mutationQueue.run(() => this.#updateUser(userId, input)));
  }

  async #updateUser(userId, input = {}) {
    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const users = await this.#loadUsers();
    const index = users.findIndex((user) => user.userId === normalizedUserId);

    if (index === -1) {
      throw this.#notFound(`User '${normalizedUserId}' not found`);
    }

    const patch = this.#normalizeUserPatch(input);

    if (patch.roleKey) {
      this.#assertKnownRole(patch.roleKey);
    }

    const next = {
      ...users[index],
      ...patch,
      updatedAt: new Date().toISOString()
    };

    users[index] = next;
    await this.#saveUsers(users);
    await this.#audit({
      action: 'user.updated',
      targetId: next.userId,
      result: 'success',
      actorUserId: input.actorUserId,
      details: { roleKey: next.roleKey, status: next.status }
    });
    return this.#userItem(next);
  }

  async deleteUser(userId, options = {}) {
    return withBindingCommitLock(() => this.mutationQueue.run(() => this.#deleteUser(userId, options)));
  }

  async #deleteUser(userId, options = {}) {
    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const users = await this.#loadUsers();
    const tombstones = await this.#loadPrincipalTombstones();
    const deletedUser = users.find((user) => user.userId === normalizedUserId);
    const next = users.filter((user) => user.userId !== normalizedUserId);

    if (next.length === users.length) {
      throw this.#notFound(`User '${normalizedUserId}' not found`);
    }

    if (this.apiTokenService?.revokeTokensForUser) {
      await this.apiTokenService.revokeTokensForUser(normalizedUserId, { revokedBy: options.actorUserId ?? 'system' });
    }

    const nextTombstones = tombstones.some((tombstone) => tombstone.userId === normalizedUserId)
      ? tombstones
      : [...tombstones, {
        userId: deletedUser.userId,
        principalGeneration: deletedUser.principalGeneration,
        deletedAt: new Date().toISOString(),
        reason: 'user-deleted'
      }];
    await this.#savePrincipalTombstones(nextTombstones);
    await this.#saveUsers(next);
    await this.#audit({
      action: 'user.deleted',
      targetId: normalizedUserId,
      result: 'success'
    });
  }



  async replaceUsers(users = [], options = {}) {
    return withBindingCommitLock(() => this.mutationQueue.run(() => this.#replaceUsers(users, options)));
  }

  async #replaceUsers(users = [], options = {}) {
    if (!Array.isArray(users)) {
      throw this.#badRequest('users must be an array');
    }

    const tombstones = await this.#loadPrincipalTombstones();
    const records = users.map((user) => {
      const normalized = this.#normalizeUserInput(user);
      this.#assertKnownRole(normalized.roleKey);
      const record = {
        ...normalized,
        principalGeneration: this.#normalizePrincipalGeneration(user.principalGeneration, normalized.userId),
        status: normalized.status ?? 'active',
        createdAt: user.createdAt ?? new Date().toISOString(),
        updatedAt: user.updatedAt ?? new Date().toISOString()
      };
      this.#assertPrincipalIdentityAvailable(record.userId, tombstones);
      return record;
    });

    const previousUsers = await this.#loadUsers();
    const nextById = new Map(records.map((user) => [user.userId, user]));
    const nextTombstones = [...tombstones];
    for (const previous of previousUsers) {
      if (nextById.has(previous.userId)) continue;
      if (nextTombstones.some((tombstone) => tombstone.userId === previous.userId)) continue;
      nextTombstones.push({
        userId: previous.userId,
        principalGeneration: previous.principalGeneration,
        deletedAt: new Date().toISOString(),
        reason: 'user-replaced'
      });
    }
    if (this.apiTokenService?.revokeTokensForUser && options.skipTokenRevocation !== true) {
      for (const previous of previousUsers) {
        const next = nextById.get(previous.userId);
        if (!next || next.principalGeneration !== previous.principalGeneration) {
          await this.apiTokenService.revokeTokensForUser(previous.userId, {
            revokedBy: options.actorUserId ?? 'system'
          });
        }
      }
    }

    await this.#savePrincipalTombstones(nextTombstones);
    await this.#saveUsers(records, { bootstrapCompleted: this.bootstrapCompleted || records.length > 0 });

    if (!options.skipAudit) {
      await this.#audit({
        action: 'users.replaced',
        targetId: 'access-management',
        result: 'success',
        actorUserId: options.actorUserId,
        details: { total: records.length }
      });
    }

    return records.map((user) => this.#userItem(user));
  }

  async getUserPermissions(userId) {
    const user = await this.#findActiveUser(userId);
    const role = this.roles.find((item) => item.roleKey === user.roleKey);

    if (!role) {
      throw this.#forbidden(`Role '${user.roleKey}' has no permissions`);
    }

    return [...role.permissions];
  }

  async getUserIdentity(userId) {
    const user = await this.#findActiveUser(userId);
    return { userId: user.userId, principalGeneration: user.principalGeneration };
  }

  async hasPermission(userId, permission) {
    const permissions = await this.getUserPermissions(userId);
    return permissions.includes(permission);
  }

  async authorize(userId, permission) {
    if (typeof userId !== 'string' || userId.trim() === '') {
      throw this.#unauthorized('Missing user authorization header');
    }

    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const permissions = await this.getUserPermissions(normalizedUserId);

    if (!permissions.includes(permission)) {
      throw this.#forbidden(`User '${normalizedUserId}' is missing permission '${permission}'`);
    }

    return {
      userId: normalizedUserId,
      permission,
      permissions
    };
  }

  async authorizeCurrentPrincipal(userId, principalGeneration, permission) {
    return this.#authorizeCurrentPrincipal(userId, principalGeneration, permission);
  }

  async withAuthorizedCurrentPrincipal(userId, principalGeneration, permission, operation) {
    if (typeof operation !== 'function') {
      throw new TypeError('operation must be a function');
    }
    return this.mutationQueue.run(async () => {
      await this.#authorizeCurrentPrincipal(userId, principalGeneration, permission);
      return operation();
    });
  }

  async #authorizeCurrentPrincipal(userId, principalGeneration, permission) {
    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const user = await this.#findActiveUser(normalizedUserId);
    if (typeof principalGeneration !== 'string' || user.principalGeneration !== principalGeneration) {
      throw this.#forbidden('OAuth actor generation is no longer current');
    }
    const role = this.roles.find((item) => item.roleKey === user.roleKey);
    if (!role || !role.permissions.includes(permission)) {
      throw this.#forbidden(`User '${normalizedUserId}' is missing permission '${permission}'`);
    }
    return { userId: normalizedUserId, principalGeneration: user.principalGeneration, permission, permissions: [...role.permissions] };
  }

  async isAuthorizationRequired() {
    const users = await this.#loadUsers();
    return users.length > 0;
  }

  async getSummary() {
    const [users, roles] = await Promise.all([this.listUsers(), this.listRoles()]);

    return {
      users: {
        total: users.length,
        byRole: this.#countBy(users, (user) => user.roleKey),
        byStatus: this.#countBy(users, (user) => user.status)
      },
      roles: {
        total: roles.length,
        items: roles
      }
    };
  }

  async #loadUsers() {
    if (!this.store?.load) {
      return this.users.map((user) => this.#normalizePersistedUser(user));
    }

    try {
      const data = await this.store.load();
      const users = Array.isArray(data?.users) ? data.users : [];
      this.bootstrapCompleted = this.bootstrapCompleted || data?.bootstrapCompleted === true || users.length > 0;
      return users.map((user) => this.#normalizePersistedUser(user));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  async #loadPrincipalTombstones() {
    if (!this.store?.loadPrincipalTombstones) {
      return this.principalTombstones.map((tombstone) => ({ ...tombstone }));
    }

    try {
      const data = await this.store.loadPrincipalTombstones();
      const tombstones = Array.isArray(data?.tombstones) ? data.tombstones : [];
      this.principalTombstones = tombstones.map((tombstone) => ({ ...tombstone }));
      return this.principalTombstones.map((tombstone) => ({ ...tombstone }));
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
  }

  async #savePrincipalTombstones(tombstones) {
    const records = tombstones.map((tombstone) => ({ ...tombstone }));
    if (!this.store?.savePrincipalTombstones) {
      this.principalTombstones = records;
      return;
    }
    await this.store.savePrincipalTombstones({ schemaVersion: 1, tombstones: records });
    this.principalTombstones = records;
  }

  #assertPrincipalIdentityAvailable(userId, tombstones) {
    if (!tombstones.some((tombstone) => tombstone.userId === userId)) return;
    const error = new Error('Principal identity is blocked by a deletion barrier');
    error.code = 'RESTORE_DELETED_IDENTITY_BARRIER';
    error.statusCode = 409;
    throw error;
  }

  async #saveUsers(users, { bootstrapCompleted = this.bootstrapCompleted || users.length > 0 } = {}) {
    const records = users.map((user) => ({ ...user }));

    if (!this.store?.save) {
      this.users = records;
      this.bootstrapCompleted = bootstrapCompleted === true;
      return;
    }

    await this.store.save({ users: records, bootstrapCompleted: bootstrapCompleted === true });
    this.bootstrapCompleted = bootstrapCompleted === true;
  }


  async #findActiveUser(userId) {
    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const users = await this.#loadUsers();
    const user = users.find((item) => item.userId === normalizedUserId);

    if (!user) {
      throw this.#unauthorized(`User '${normalizedUserId}' is not known`);
    }

    if (user.status !== 'active') {
      throw this.#forbidden(`User '${normalizedUserId}' is disabled`);
    }

    return user;
  }


  async #audit({ action, targetId, result, actorUserId = null, details = null }) {
    if (!this.auditLogService?.record) {
      return;
    }

    await this.auditLogService.record({
      userId: actorUserId,
      action,
      targetType: 'user',
      targetId,
      result,
      details
    });
  }

  #normalizeUserInput(input) {
    this.#assertKnownRole(input.roleKey);
    return {
      userId: this.#normalizeIdentity(input.userId, 'userId'),
      displayName: this.#normalizeRequiredString(input.displayName, 'displayName'),
      email: this.#normalizeOptionalString(input.email),
      roleKey: this.#normalizeIdentity(input.roleKey, 'roleKey'),
      status: this.#normalizeStatus(input.status ?? 'active')
    };
  }

  #normalizePersistedUser(user) {
    const normalized = { ...user };
    normalized.principalGeneration = this.#normalizePrincipalGeneration(user.principalGeneration, normalized.userId);
    return normalized;
  }

  #normalizePrincipalGeneration(value, userId) {
    if (value !== undefined && value !== null) return this.#normalizeIdentity(value, 'principalGeneration');
    return `legacy:${userId}`;
  }

  #normalizeFirstAdministratorInput(input) {
    const roleKey = input.roleKey === undefined
      ? 'admin'
      : this.#normalizeIdentity(input.roleKey, 'roleKey');
    if (roleKey !== 'admin') {
      throw this.#badRequest('Bootstrap first user roleKey must be admin');
    }

    const status = input.status === undefined
      ? 'active'
      : this.#normalizeStatus(input.status);
    if (status !== 'active') {
      throw this.#badRequest('Bootstrap first user status must be active');
    }

    return {
      userId: this.#normalizeIdentity(input.userId, 'userId'),
      displayName: this.#normalizeRequiredString(input.displayName, 'displayName'),
      email: this.#normalizeOptionalString(input.email),
      roleKey: 'admin',
      status: 'active'
    };
  }

  #normalizeBootstrapSecret(value) {
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < BOOTSTRAP_SECRET_MIN_BYTES
      || KNOWN_BOOTSTRAP_PLACEHOLDERS.has(value)
      || !meetsBootstrapEntropyRequirement(value)) {
      return null;
    }
    return value;
  }

  #timingSafeSecretMatch(candidate) {
    if (typeof candidate !== 'string') {
      return false;
    }

    const configuredDigest = crypto.createHash('sha256').update(this.bootstrapSecret, 'utf8').digest();
    const candidateDigest = crypto.createHash('sha256').update(candidate, 'utf8').digest();
    return crypto.timingSafeEqual(configuredDigest, candidateDigest);
  }

  #bootstrapUnavailable() {
    const error = new Error('Bootstrap is not configured');
    error.statusCode = 503;
    error.code = 'BOOTSTRAP_UNAVAILABLE';
    return error;
  }

  #bootstrapClosed() {
    const error = new Error('Bootstrap is no longer available');
    error.statusCode = 403;
    error.code = 'BOOTSTRAP_CLOSED';
    return error;
  }

  #bootstrapProofInvalid() {
    const error = new Error('Bootstrap proof is invalid');
    error.statusCode = 403;
    error.code = 'BOOTSTRAP_PROOF_INVALID';
    return error;
  }

  #normalizeUserPatch(input) {
    const patch = {};

    if (input.displayName !== undefined) {
      patch.displayName = this.#normalizeRequiredString(input.displayName, 'displayName');
    }
    if (input.email !== undefined) {
      patch.email = this.#normalizeOptionalString(input.email);
    }
    if (input.roleKey !== undefined) {
      patch.roleKey = this.#normalizeIdentity(input.roleKey, 'roleKey');
    }
    if (input.status !== undefined) {
      patch.status = this.#normalizeStatus(input.status);
    }

    return patch;
  }

  #normalizeRequiredString(value, name) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw this.#badRequest(`${name} must be a non-empty string`);
    }

    return value.trim();
  }

  #normalizeIdentity(value, name) {
    try { return validateNamedIdentifier(name, value); } catch (error) {
      if (error instanceof AuthorizationIdentifierError) throw this.#badRequest(`${name} is invalid`);
      throw error;
    }
  }

  #normalizeOptionalString(value) {
    if (value === undefined || value === null || value === '') {
      return null;
    }

    if (typeof value !== 'string') {
      throw this.#badRequest('email must be a string');
    }

    return value.trim();
  }

  #normalizeStatus(value) {
    const status = this.#normalizeRequiredString(value, 'status');
    const allowed = new Set(['active', 'disabled']);

    if (!allowed.has(status)) {
      throw this.#badRequest('status must be active or disabled');
    }

    return status;
  }

  #assertKnownRole(roleKey) {
    if (!this.roles.some((role) => role.roleKey === roleKey)) {
      throw this.#badRequest(`Unknown role '${roleKey}'`);
    }
    this.#normalizeIdentity(roleKey, 'roleKey');
  }

  #userItem(user) {
    return {
      userId: user.userId,
      displayName: user.displayName,
      email: user.email ?? null,
      roleKey: user.roleKey,
      status: user.status,
      createdAt: user.createdAt ?? null,
      updatedAt: user.updatedAt ?? null
    };
  }

  #roleItem(role) {
    return {
      roleKey: role.roleKey,
      displayName: role.displayName,
      description: role.description,
      permissions: [...role.permissions]
    };
  }

  #countBy(items, keyFn) {
    return items.reduce((counts, item) => {
      const key = keyFn(item) ?? 'unknown';
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    }, {});
  }


  #unauthorized(message) {
    const error = new Error(message);
    error.statusCode = 401;
    error.code = 'UNAUTHORIZED';
    return error;
  }

  #forbidden(message) {
    const error = new Error(message);
    error.statusCode = 403;
    error.code = 'FORBIDDEN';
    return error;
  }

  #badRequest(message) {
    const error = new Error(message);
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    return error;
  }

  #notFound(message) {
    const error = new Error(message);
    error.statusCode = 404;
    error.code = 'NOT_FOUND';
    return error;
  }
}
