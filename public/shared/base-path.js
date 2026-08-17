// This file is part of Sekalum.
//
// Sekalum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

export function detectedBasePath(pathname = globalThis.location?.pathname ?? '/') {
  const match = pathname.match(/^(.*)\/(?:admin|consumer)(?:\/|$)/);
  return match?.[1] ?? '';
}

export function applicationPath(path, pathname = globalThis.location?.pathname ?? '/') {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${detectedBasePath(pathname)}${normalizedPath}`;
}
