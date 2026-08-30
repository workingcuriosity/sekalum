import fs from 'node:fs/promises';
import path from 'node:path';

const BACKUP_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function validateBackupIdentifier(value, fieldName = 'backupId') {
  if (typeof value !== 'string' || !BACKUP_IDENTIFIER_PATTERN.test(value)) {
    const error = new Error(`${fieldName} must be a single backup identifier`);
    error.code = 'BACKUP_PATH_INVALID';
    error.statusCode = 400;
    throw error;
  }
  return value;
}

export function backupFilePath(rootPath, segments) {
  const root = path.resolve(rootPath);
  const filePath = path.resolve(root, ...segments);
  const relative = path.relative(root, filePath);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw backupPathError('Backup path escapes the canonical backup root');
  }
  return filePath;
}

export async function assertBackupPath(filePath, rootPath, { kind = 'file', allowMissing = false } = {}) {
  const root = path.resolve(rootPath);
  const resolvedPath = path.resolve(filePath);
  const relative = path.relative(root, resolvedPath);
  if ((!relative && kind !== 'directory') || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw backupPathError('Backup path escapes the canonical backup root');
  }

  const segments = relative.split(path.sep);
  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    let stats;
    try {
      stats = await fs.lstat(current);
    } catch (error) {
      if (error?.code === 'ENOENT' && allowMissing) return resolvedPath;
      throw error;
    }

    if (stats.isSymbolicLink()) {
      throw backupPathError('Symlinks are not allowed in the backup path');
    }

    if (current === resolvedPath) {
      if (kind === 'file' && !stats.isFile()) {
        throw backupPathError('Backup target must be a regular file');
      }
      if (kind === 'directory' && !stats.isDirectory()) {
        throw backupPathError('Backup directory must be a directory');
      }
    }
  }

  return resolvedPath;
}

export function backupPathError(message) {
  const error = new Error(message);
  error.code = 'BACKUP_PATH_INVALID';
  error.statusCode = 400;
  return error;
}
