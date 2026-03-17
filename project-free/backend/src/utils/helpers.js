import crypto from 'crypto';

/**
 * Generate a sequential ID like RSK-2024-001
 */
export function generateId(prefix, count) {
  const year  = new Date().getFullYear();
  const seq   = String(count + 1).padStart(3, '0');
  return `${prefix}-${year}-${seq}`;
}

/**
 * Safe pagination params
 */
export function parsePagination(query) {
  const page  = Math.max(1, parseInt(query.page)  || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 20));
  const from  = (page - 1) * limit;
  const to    = from + limit - 1;
  return { page, limit, from, to };
}

/**
 * SHA-256 checksum
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Strip undefined keys from an object (for partial updates)
 */
export function stripUndefined(obj) {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined)
  );
}

/**
 * Standard API response envelope
 */
export function ok(res, data, meta = {}) {
  return res.json({ success: true, data, ...meta });
}

export function created(res, data) {
  return res.status(201).json({ success: true, data });
}

export function noContent(res) {
  return res.status(204).send();
}
