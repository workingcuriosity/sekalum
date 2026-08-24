import fs from 'fs/promises';
import crypto from 'node:crypto';
import path from 'path';

export class JsonStore {
  async load(filePath) {

  const content = await fs.readFile(filePath, 'utf8');

  return JSON.parse(content);
}

  async save(filePath, data) {
    await this.ensureDirectory(path.dirname(filePath));

    const content = JSON.stringify(data, null, 2);
    await fs.writeFile(filePath, `${content}\n`, 'utf8');
  }

  async saveAtomic(filePath, data) {
    const directory = path.dirname(filePath);
    await this.ensureDirectory(directory);

    const temporaryPath = path.join(
      directory,
      `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`
    );
    const content = `${JSON.stringify(data, null, 2)}\n`;

    try {
      await fs.writeFile(temporaryPath, content, { encoding: 'utf8', flag: 'wx' });
      await fs.rename(temporaryPath, filePath);
    } catch (error) {
      try {
        await fs.unlink(temporaryPath);
      } catch {
        // Cleanup is best effort; the original error remains authoritative.
      }
      throw error;
    }
  }

  async exists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async delete(filePath) {
    if (!(await this.exists(filePath))) {
      return false;
    }

    await fs.unlink(filePath);
    return true;
  }

  async ensureDirectory(directoryPath) {
    await fs.mkdir(directoryPath, { recursive: true });
  }
}
