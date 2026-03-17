import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { sha256 } from '../../utils/helpers.js';
import {
  BCRYPT_ROUNDS, JWT_ACCESS_EXPIRY, JWT_REFRESH_EXPIRY,
  MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION,
} from '../../config/constants.js';

const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || JWT_SECRET + '_refresh';

function signAccess(userId, orgId, role) {
  return jwt.sign({ sub: userId, org_id: orgId, role }, JWT_SECRET, { expiresIn: JWT_ACCESS_EXPIRY });
}

function signRefresh(userId) {
  const token = jwt.sign({ sub: userId, type: 'refresh' }, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRY });
  return token;
}

export async function register({ orgId, email, password, firstName, lastName, role = 'viewer' }) {
  // Check duplicate
  const { data: existing } = await supabase
    .from('users').select('id').eq('org_id', orgId).eq('email', email).single();
  if (existing) throw AppError.conflict('Email already registered');

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { data: user, error } = await supabase
    .from('users')
    .insert({ org_id: orgId, email, password_hash: passwordHash, first_name: firstName, last_name: lastName, role })
    .select('id, org_id, email, role, first_name, last_name, mfa_enabled')
    .single();

  if (error) throw new AppError(error.message, 500);
  return user;
}

export async function login({ email, orgSlug, password, totpCode }) {
  // Resolve org
  const { data: org } = await supabase.from('organizations').select('id').eq('slug', orgSlug).single();
  if (!org) throw AppError.unauthorized('Invalid organization');

  // Fetch user
  const { data: user } = await supabase
    .from('users')
    .select('id, org_id, email, password_hash, role, is_active, mfa_enabled, mfa_secret, failed_login_attempts, locked_until, first_name, last_name')
    .eq('org_id', org.id)
    .eq('email', email)
    .single();

  if (!user) throw AppError.unauthorized('Invalid credentials');
  if (!user.is_active) throw AppError.unauthorized('Account deactivated');

  // Lockout check
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    throw AppError.unauthorized('Account temporarily locked. Try again later.');
  }

  const passwordValid = await bcrypt.compare(password, user.password_hash);
  if (!passwordValid) {
    const attempts = user.failed_login_attempts + 1;
    const updateData = { failed_login_attempts: attempts };
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      updateData.locked_until = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
    }
    await supabase.from('users').update(updateData).eq('id', user.id);
    throw AppError.unauthorized('Invalid credentials');
  }

  // MFA check
  if (user.mfa_enabled) {
    if (!totpCode) throw AppError.unauthorized('MFA code required');
    const valid = speakeasy.totp.verify({
      secret:   user.mfa_secret,
      encoding: 'base32',
      token:    totpCode,
      window:   1,
    });
    if (!valid) throw AppError.unauthorized('Invalid MFA code');
  }

  // Reset failed attempts, update last login
  await supabase.from('users').update({
    failed_login_attempts: 0,
    locked_until:          null,
    last_login_at:         new Date().toISOString(),
  }).eq('id', user.id);

  // Issue tokens
  const accessToken  = signAccess(user.id, user.org_id, user.role);
  const refreshToken = signRefresh(user.id);

  // Persist refresh token hash
  await supabase.from('refresh_tokens').insert({
    user_id:    user.id,
    token_hash: sha256(refreshToken),
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });

  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id, email: user.email, role: user.role,
      firstName: user.first_name, lastName: user.last_name,
      mfaEnabled: user.mfa_enabled, orgId: user.org_id,
    },
  };
}

export async function refreshAccessToken(refreshToken) {
  let payload;
  try {
    payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
  } catch {
    throw AppError.unauthorized('Invalid refresh token');
  }

  const tokenHash = sha256(refreshToken);
  const { data: stored } = await supabase
    .from('refresh_tokens')
    .select('id, revoked, expires_at, user_id')
    .eq('token_hash', tokenHash)
    .single();

  if (!stored || stored.revoked || new Date(stored.expires_at) < new Date()) {
    throw AppError.unauthorized('Refresh token expired or revoked');
  }

  const { data: user } = await supabase
    .from('users')
    .select('id, org_id, role, is_active')
    .eq('id', stored.user_id)
    .single();

  if (!user?.is_active) throw AppError.unauthorized('User inactive');

  const newAccess = signAccess(user.id, user.org_id, user.role);
  return { accessToken: newAccess };
}

export async function logout(refreshToken) {
  if (!refreshToken) return;
  const tokenHash = sha256(refreshToken);
  await supabase.from('refresh_tokens').update({ revoked: true }).eq('token_hash', tokenHash);
}

export async function setupMfa(userId) {
  const secret = speakeasy.generateSecret({ name: 'GRC Platform', length: 20 });
  // Store secret temporarily (not yet active until verified)
  await supabase.from('users').update({ mfa_secret: secret.base32 }).eq('id', userId);
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  return { secret: secret.base32, qrCodeUrl };
}

export async function verifyAndEnableMfa(userId, totpCode) {
  const { data: user } = await supabase.from('users').select('mfa_secret').eq('id', userId).single();
  if (!user?.mfa_secret) throw AppError.badRequest('MFA setup not initiated');

  const valid = speakeasy.totp.verify({
    secret: user.mfa_secret, encoding: 'base32', token: totpCode, window: 1,
  });
  if (!valid) throw AppError.badRequest('Invalid TOTP code');

  await supabase.from('users').update({ mfa_enabled: true }).eq('id', userId);
  return { mfaEnabled: true };
}

export async function disableMfa(userId, password) {
  const { data: user } = await supabase.from('users').select('password_hash').eq('id', userId).single();
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) throw AppError.unauthorized('Invalid password');
  await supabase.from('users').update({ mfa_enabled: false, mfa_secret: null }).eq('id', userId);
  return { mfaEnabled: false };
}

export async function changePassword(userId, currentPassword, newPassword) {
  const { data: user } = await supabase.from('users').select('password_hash').eq('id', userId).single();
  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) throw AppError.unauthorized('Current password is incorrect');

  const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users')
    .update({ password_hash: hash, password_changed_at: new Date().toISOString() })
    .eq('id', userId);

  // Revoke all refresh tokens on password change
  await supabase.from('refresh_tokens').update({ revoked: true }).eq('user_id', userId);
  return { message: 'Password changed successfully' };
}
