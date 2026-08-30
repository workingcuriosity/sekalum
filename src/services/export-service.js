const EXPORT_RESOURCES = Object.freeze(['audit-log', 'users', 'roles', 'providers', 'scheduler', 'status']);
const EXPORT_FORMATS = Object.freeze(['json', 'csv']);
const CSV_FORMULA_PREFIXES = /^[=+\-@\t\r]/;

export class ExportService {
  constructor({ managementService, accessManagementService, auditLogService, clock = () => new Date() } = {}) {
    if (!managementService) {
      throw new Error('ExportService requires ManagementService');
    }

    this.managementService = managementService;
    this.accessManagementService = accessManagementService;
    this.auditLogService = auditLogService;
    this.clock = clock;
  }

  async export(resource, options = {}) {
    const normalizedResource = this.#normalizeResource(resource);
    const format = this.#normalizeFormat(options.format ?? 'json');
    const data = await this.#loadResource(normalizedResource, options.filters ?? {});
    const generatedAt = this.#timestamp();

    if (format === 'csv') {
      return {
        resource: normalizedResource,
        format,
        generatedAt,
        filename: this.#filename(normalizedResource, format, generatedAt),
        contentType: 'text/csv; charset=utf-8',
        content: this.#toCsv(data)
      };
    }

    return {
      resource: normalizedResource,
      format,
      generatedAt,
      filename: this.#filename(normalizedResource, format, generatedAt),
      contentType: 'application/json; charset=utf-8',
      content: JSON.stringify({ resource: normalizedResource, generatedAt, data }, null, 2),
      data
    };
  }

  async listResources() {
    return EXPORT_RESOURCES.map((resource) => ({ resource, formats: [...EXPORT_FORMATS] }));
  }

  async #loadResource(resource, filters) {
    if (resource === 'audit-log') {
      if (typeof this.auditLogService?.list !== 'function') {
        throw new Error('ExportService requires AuditLogService.list() for audit-log exports');
      }
      return this.auditLogService.list(filters);
    }

    if (resource === 'users') {
      if (typeof this.accessManagementService?.listUsers !== 'function') {
        throw new Error('ExportService requires AccessManagementService.listUsers() for users exports');
      }
      return this.accessManagementService.listUsers();
    }

    if (resource === 'roles') {
      if (typeof this.accessManagementService?.listRoles !== 'function') {
        throw new Error('ExportService requires AccessManagementService.listRoles() for roles exports');
      }
      return this.accessManagementService.listRoles();
    }

    if (resource === 'providers') {
      return this.managementService.getProviders();
    }

    if (resource === 'scheduler') {
      return this.managementService.getScheduler();
    }

    return this.managementService.getStatus();
  }

  #toCsv(data) {
    const rows = Array.isArray(data) ? data : this.#flattenManagementData(data);
    const normalizedRows = rows.map((row) => this.#flattenObject(row));
    const headers = [...normalizedRows.reduce((keys, row) => {
      for (const key of Object.keys(row)) {
        keys.add(key);
      }
      return keys;
    }, new Set())];

    if (headers.length === 0) {
      return '';
    }

    return [
      headers.map((header) => this.#escapeCsv(header)).join(','),
      ...normalizedRows.map((row) => headers.map((header) => this.#escapeCsv(row[header])).join(','))
    ].join('\n');
  }

  #flattenManagementData(data) {
    if (Array.isArray(data?.items)) {
      return data.items;
    }

    if (Array.isArray(data?.roles?.items)) {
      return data.roles.items;
    }

    return [data ?? {}];
  }

  #flattenObject(value, prefix = '', target = {}) {
    if (value === null || value === undefined) {
      if (prefix) target[prefix] = '';
      return target;
    }

    if (Array.isArray(value)) {
      target[prefix] = value.join('|');
      return target;
    }

    if (typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        this.#flattenObject(child, prefix ? `${prefix}.${key}` : key, target);
      }
      return target;
    }

    target[prefix] = value;
    return target;
  }

  #escapeCsv(value) {
    const rawText = value === null || value === undefined ? '' : String(value);
    const text = CSV_FORMULA_PREFIXES.test(rawText) ? `'${rawText}` : rawText;
    if (!/[",\n\r]/.test(text)) {
      return text;
    }
    return `"${text.replaceAll('"', '""')}"`;
  }

  #normalizeResource(value) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw this.#badRequest('resource must be a non-empty string');
    }

    const resource = value.trim();
    if (!EXPORT_RESOURCES.includes(resource)) {
      throw this.#badRequest(`resource must be one of: ${EXPORT_RESOURCES.join(', ')}`);
    }
    return resource;
  }

  #normalizeFormat(value) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw this.#badRequest('format must be json or csv');
    }

    const format = value.trim().toLowerCase();
    if (!EXPORT_FORMATS.includes(format)) {
      throw this.#badRequest('format must be json or csv');
    }
    return format;
  }

  #timestamp() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    return date.toISOString();
  }

  #filename(resource, format, generatedAt) {
    const stamp = generatedAt.replaceAll(':', '-').replaceAll('.', '-');
    return `credential-hub-${resource}-${stamp}.${format}`;
  }

  #badRequest(message) {
    const error = new Error(message);
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    return error;
  }
}
