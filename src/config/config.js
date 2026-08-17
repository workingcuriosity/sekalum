// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
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
