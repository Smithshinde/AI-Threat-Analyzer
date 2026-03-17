import { supabase } from '../config/database.js';
import logger from '../utils/logger.js';

/**
 * Append an immutable entry to audit_logs.
 * Call from controllers after successful mutations.
 */
export async function writeAuditLog({ orgId, userId, action, resourceType, resourceId, oldValues, newValues, req }) {
  try {
    await supabase.from('audit_logs').insert({
      org_id:        orgId,
      user_id:       userId,
      action,
      resource_type: resourceType,
      resource_id:   resourceId,
      old_values:    oldValues || null,
      new_values:    newValues || null,
      ip_address:    req?.ip || null,
      user_agent:    req?.headers?.['user-agent'] || null,
    });
  } catch (err) {
    // Audit log failure must never break the main flow
    logger.error('Failed to write audit log', { action, error: err.message });
  }
}

/**
 * Express middleware to auto-log all mutating requests.
 * Attach after route handlers via res.on('finish').
 */
export function auditMiddleware(req, res, next) {
  const originalJson = res.json.bind(res);
  res.json = function (body) {
    if (req.user && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const action = `${req.method.toLowerCase()}.${req.route?.path || req.path}`;
      writeAuditLog({
        orgId:        req.user.org_id,
        userId:       req.user.id,
        action,
        resourceType: null,
        resourceId:   null,
        newValues:    body?.data || null,
        req,
      });
    }
    return originalJson(body);
  };
  next();
}
