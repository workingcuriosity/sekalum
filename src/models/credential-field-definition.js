const SUPPORTED_TYPES = new Set([
  'text',
  'password',
  'textarea',
  'select',
  'boolean',
  'integer',
  'url',
  'email',
  'api-key',
  'oauth-scope',
  'hidden'
]);

const RUNTIME_PUBLIC_FORBIDDEN_KEYS = new Set([
  'adapter',
  'adapterKey',
  'credentialId',
  'credentialMethodKey',
  'providerAdapter',
  'providerConfigurationId',
  'providerKey',
  'route',
  'routing'
]);

export class CredentialFieldDefinition {
  constructor({
    key,
    label,
    type = 'text',
    required = false,
    secret = false,
    description = null,
    placeholder = null,
    defaultValue = null,
    validation = null,
    options = null,
    csvAliases = [],
    group = 'Credential-Daten',
    section = 'accountCredentials',
    displayOrder = 0,
    readonly = false,
    visible = true,
    userConfigurable = true,
    systemManaged = false,
    runtimePublic = false,
    materialization = 'stored'
  } = {}) {
    if (typeof key !== 'string' || key.trim() === '') {
      throw new Error("CredentialFieldDefinition: 'key' is required");
    }

    if (typeof label !== 'string' || label.trim() === '') {
      throw new Error(`CredentialFieldDefinition '${key}': label is required`);
    }

    if (!SUPPORTED_TYPES.has(type)) {
      throw new Error(`CredentialFieldDefinition '${key}': unsupported type '${type}'`);
    }

    if (secret && defaultValue !== null) {
      throw new Error(`CredentialFieldDefinition '${key}': secret fields must not define defaultValue`);
    }

    if (!Array.isArray(csvAliases) || csvAliases.some((alias) => typeof alias !== 'string' || alias.trim() === '')) {
      throw new Error(`CredentialFieldDefinition '${key}': csvAliases must contain non-empty strings`);
    }

    if (options !== null && !Array.isArray(options)) {
      throw new Error(`CredentialFieldDefinition '${key}': options must be an array or null`);
    }

    if (typeof runtimePublic !== 'boolean') {
      throw new Error(`CredentialFieldDefinition '${key}': runtimePublic must be a boolean`);
    }
    if (!['stored', 'derived'].includes(materialization)) {
      throw new Error(`CredentialFieldDefinition '${key}': unsupported materialization '${materialization}'`);
    }
    if (materialization === 'derived' && (!secret || userConfigurable || !systemManaged)) {
      throw new Error(`CredentialFieldDefinition '${key}': derived fields must be secret, system-managed and non-configurable`);
    }

    if (runtimePublic && section !== 'providerConfiguration') {
      throw new Error(`CredentialFieldDefinition '${key}': runtimePublic fields must use the providerConfiguration section`);
    }

    if (runtimePublic && secret) {
      throw new Error(`CredentialFieldDefinition '${key}': secret fields must not be Runtime-Public`);
    }

    if (runtimePublic && RUNTIME_PUBLIC_FORBIDDEN_KEYS.has(key.trim())) {
      throw new Error(`CredentialFieldDefinition '${key}': internal fields must not be Runtime-Public`);
    }

    this.key = key.trim();
    this.label = label.trim();
    this.type = type;
    this.required = Boolean(required);
    this.secret = Boolean(secret);
    this.description = description;
    this.placeholder = placeholder;
    this.defaultValue = defaultValue;
    this.validation = validation ? Object.freeze({ ...validation }) : null;
    this.options = options ? Object.freeze(options.map((option) => Object.freeze({ ...option }))) : null;
    this.csvAliases = Object.freeze([...new Set([this.key, ...csvAliases.map((alias) => alias.trim())])]);
    this.group = group;
    this.section = section;
    this.displayOrder = Number(displayOrder) || 0;
    this.readonly = Boolean(readonly);
    this.visible = Boolean(visible);
    this.userConfigurable = Boolean(userConfigurable);
    this.systemManaged = Boolean(systemManaged);
    this.runtimePublic = runtimePublic;
    this.materialization = materialization;

    Object.freeze(this);
  }

  toJSON() {
    return {
      key: this.key,
      label: this.label,
      type: this.type,
      required: this.required,
      secret: this.secret,
      description: this.description,
      placeholder: this.placeholder,
      defaultValue: this.defaultValue,
      validation: this.validation,
      options: this.options,
      csvAliases: [...this.csvAliases],
      group: this.group,
      section: this.section,
      inputType: this.type,
      displayOrder: this.displayOrder,
      readonly: this.readonly,
      visible: this.visible,
      userConfigurable: this.userConfigurable,
      systemManaged: this.systemManaged,
      ...(this.materialization !== 'stored' ? { materialization: this.materialization } : {})
    };
  }

  static from(value) {
    return value instanceof CredentialFieldDefinition
      ? value
      : new CredentialFieldDefinition(value);
  }
}
