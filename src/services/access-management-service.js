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

export class AccessManagementService {
  constructor({ store = null, auditLogService = null } = {}) {
    this.store = store;
    this.auditLogService = auditLogService;
    this.roles = DEFAULT_ROLES.map((role) => ({ ...role, permissions: [...role.permissions] }));
    this.users = [];
  }

  async listRoles() {
    return this.roles.map((role) => this.#roleItem(role));
  }

  async listUsers() {
    const records = await this.#loadUsers();
    return records.map((user) => this.#userItem(user));
  }

  async createUser(input = {}) {
    const user = this.#normalizeUserInput(input);
    const users = await this.#loadUsers();

    if (users.some((item) => item.userId === user.userId)) {
      throw this.#badRequest(`User '${user.userId}' already exists`);
    }

    this.#assertKnownRole(user.roleKey);

    const now = new Date().toISOString();
    const record = {
      ...user,
      status: user.status ?? 'active',
      createdAt: now,
      updatedAt: now
    };

    users.push(record);
    await this.#saveUsers(users);
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
    const normalizedUserId = this.#normalizeRequiredString(userId, 'userId');
    const users = await this.#loadUsers();
    const next = users.filter((user) => user.userId !== normalizedUserId);

    if (next.length === users.length) {
      throw this.#notFound(`User '${normalizedUserId}' not found`);
    }

    await this.#saveUsers(next);
    await this.#audit({
      action: 'user.deleted',
      targetId: normalizedUserId,
      result: 'success'
    });
  }



  async replaceUsers(users = [], options = {}) {
    if (!Array.isArray(users)) {
      throw this.#badRequest('users must be an array');
    }

    const records = users.map((user) => {
      const normalized = this.#normalizeUserInput(user);
      this.#assertKnownRole(normalized.roleKey);
      return {
        ...normalized,
        status: normalized.status ?? 'active',
        createdAt: user.createdAt ?? new Date().toISOString(),
        updatedAt: user.updatedAt ?? new Date().toISOString()
      };
    });

    await this.#saveUsers(records);

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
      return this.users.map((user) => ({ ...user }));
    }

    try {
      const data = await this.store.load();
      const users = Array.isArray(data?.users) ? data.users : [];
      return users.map((user) => ({ ...user }));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  async #saveUsers(users) {
    const records = users.map((user) => ({ ...user }));

    if (!this.store?.save) {
      this.users = records;
      return;
    }

    await this.store.save({ users: records });
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
    return {
      userId: this.#normalizeRequiredString(input.userId, 'userId'),
      displayName: this.#normalizeRequiredString(input.displayName, 'displayName'),
      email: this.#normalizeOptionalString(input.email),
      roleKey: this.#normalizeRequiredString(input.roleKey, 'roleKey'),
      status: this.#normalizeStatus(input.status ?? 'active')
    };
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
      patch.roleKey = this.#normalizeRequiredString(input.roleKey, 'roleKey');
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
