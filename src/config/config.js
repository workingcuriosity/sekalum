// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

export class Config {
  constructor(env = {}) {
    this.env = env;
    this.nodeEnv = env.NODE_ENV || 'development';
  }

  get(key, fallback = null) {
    return this.env[key] ?? fallback;
  }

  require(key) {
    const value = this.get(key);

    if (!value) {
      throw new Error(`Missing required config value: ${key}`);
    }

    return value;
  }
}
