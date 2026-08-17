// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import { bootstrap } from '../bootstrap.js';

const app = await bootstrap();

await app.runRefresh();

process.exit(0);
