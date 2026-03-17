import { PERMISSIONS, ROLE_HIERARCHY } from '../config/constants.js';
import { AppError } from '../utils/AppError.js';

/**
 * Check that req.user has one of the allowed roles for a given permission.
 * Usage: authorize('risks:write')
 */
export function authorize(permission) {
  return (req, _res, next) => {
    if (!req.user) return next(AppError.unauthorized());

    const allowed = PERMISSIONS[permission];
    if (!allowed) return next(AppError.forbidden(`Unknown permission: ${permission}`));

    if (!allowed.includes(req.user.role)) {
      return next(AppError.forbidden(`Role '${req.user.role}' cannot perform '${permission}'`));
    }
    next();
  };
}

/**
 * Require minimum role level (higher in hierarchy)
 */
export function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.user) return next(AppError.unauthorized());
    if (!roles.includes(req.user.role)) {
      return next(AppError.forbidden('Insufficient role'));
    }
    next();
  };
}

/**
 * Ensure the tenant in the request matches the authenticated user's org
 */
export function enforceOrgScope(req, _res, next) {
  const paramOrgId = req.params.orgId || req.body.org_id;
  if (paramOrgId && paramOrgId !== req.user.org_id && req.user.role !== 'super_admin') {
    return next(AppError.forbidden('Cross-tenant access denied'));
  }
  next();
}
