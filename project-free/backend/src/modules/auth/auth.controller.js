import { validationResult } from 'express-validator';
import * as authService from './auth.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

function handleValidation(req) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const err = new Error('Validation failed');
    err.type = 'validation';
    err.errors = errors.array();
    throw err;
  }
}

export async function register(req, res, next) {
  try {
    handleValidation(req);
    const user = await authService.register({ orgId: req.user.org_id, ...req.body });
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'user.create', resourceType: 'user', resourceId: user.id, newValues: { email: user.email, role: user.role }, req });
    created(res, user);
  } catch (err) { next(err); }
}

export async function login(req, res, next) {
  try {
    handleValidation(req);
    const result = await authService.login(req.body);
    ok(res, result);
  } catch (err) { next(err); }
}

export async function refresh(req, res, next) {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return next(require('../../utils/AppError.js').AppError.badRequest('refreshToken required'));
    const result = await authService.refreshAccessToken(refreshToken);
    ok(res, result);
  } catch (err) { next(err); }
}

export async function logout(req, res, next) {
  try {
    const { refreshToken } = req.body;
    await authService.logout(refreshToken);
    res.json({ success: true, message: 'Logged out' });
  } catch (err) { next(err); }
}

export async function setupMfa(req, res, next) {
  try {
    const result = await authService.setupMfa(req.user.id);
    ok(res, result);
  } catch (err) { next(err); }
}

export async function verifyMfa(req, res, next) {
  try {
    handleValidation(req);
    const result = await authService.verifyAndEnableMfa(req.user.id, req.body.code);
    ok(res, result);
  } catch (err) { next(err); }
}

export async function disableMfa(req, res, next) {
  try {
    handleValidation(req);
    const result = await authService.disableMfa(req.user.id, req.body.password);
    ok(res, result);
  } catch (err) { next(err); }
}

export async function changePassword(req, res, next) {
  try {
    handleValidation(req);
    const result = await authService.changePassword(req.user.id, req.body.currentPassword, req.body.newPassword);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'user.password_change', resourceType: 'user', resourceId: req.user.id, req });
    ok(res, result);
  } catch (err) { next(err); }
}

export async function getProfile(req, res, next) {
  try {
    ok(res, req.user);
  } catch (err) { next(err); }
}
