import jwt from 'jsonwebtoken';
import { AppError } from '../utils/AppError.js';
import { supabase } from '../config/database.js';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET must be set');

/**
 * Verify JWT and attach user context to req.user
 */
export async function authenticate(req, _res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw AppError.unauthorized('Missing or invalid Authorization header');
    }

    const token = authHeader.slice(7);
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      const msg = e.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
      throw AppError.unauthorized(msg);
    }

    // Fetch fresh user to catch deactivated accounts
    const { data: user, error } = await supabase
      .from('users')
      .select('id, org_id, email, role, is_active, first_name, last_name')
      .eq('id', payload.sub)
      .single();

    if (error || !user) throw AppError.unauthorized('User not found');
    if (!user.is_active) throw AppError.unauthorized('Account deactivated');

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Optional auth — attaches user if token is present, doesn't fail if absent
 */
export async function optionalAuth(req, _res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return next();

  try {
    const token   = authHeader.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase
      .from('users')
      .select('id, org_id, email, role, is_active')
      .eq('id', payload.sub)
      .single();
    if (user?.is_active) req.user = user;
  } catch (_) { /* ignore */ }
  next();
}
