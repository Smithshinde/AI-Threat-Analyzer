export const ROLES = {
  SUPER_ADMIN:  'super_admin',
  ADMIN:        'admin',
  CISO:         'ciso',
  RISK_MANAGER: 'risk_manager',
  AUDITOR:      'auditor',
  VIEWER:       'viewer',
};

export const ROLE_HIERARCHY = {
  super_admin:  6,
  admin:        5,
  ciso:         4,
  risk_manager: 3,
  auditor:      2,
  viewer:       1,
};

// Permissions matrix: resource -> minimum role required
export const PERMISSIONS = {
  // Risks
  'risks:read':   [ROLES.VIEWER, ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'risks:write':  [ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'risks:delete': [ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Controls
  'controls:read':   [ROLES.VIEWER, ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'controls:write':  [ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'controls:delete': [ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Compliance
  'compliance:read':  [ROLES.VIEWER, ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'compliance:write': [ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Policies
  'policies:read':    [ROLES.VIEWER, ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'policies:write':   [ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'policies:approve': [ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Incidents
  'incidents:read':   [ROLES.VIEWER, ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'incidents:write':  [ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Evidence
  'evidence:read':  [ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'evidence:write': [ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Users
  'users:read':   [ROLES.ADMIN, ROLES.SUPER_ADMIN],
  'users:write':  [ROLES.ADMIN, ROLES.SUPER_ADMIN],
  // Reports
  'reports:read': [ROLES.AUDITOR, ROLES.RISK_MANAGER, ROLES.CISO, ROLES.ADMIN, ROLES.SUPER_ADMIN],
};

export const RISK_SCORE_MATRIX = {
  likelihood: { rare: 1, unlikely: 2, possible: 3, likely: 4, almost_certain: 5 },
  impact:     { negligible: 1, minor: 2, moderate: 3, major: 4, critical: 5 },
};

export const RISK_RATING = (score) => {
  if (score >= 15) return { rating: 'Critical', color: 'red' };
  if (score >= 9)  return { rating: 'High',     color: 'orange' };
  if (score >= 4)  return { rating: 'Medium',   color: 'yellow' };
  return              { rating: 'Low',      color: 'green' };
};

export const JWT_ACCESS_EXPIRY  = '15m';
export const JWT_REFRESH_EXPIRY = '7d';
export const BCRYPT_ROUNDS      = 12;
export const MAX_LOGIN_ATTEMPTS = 5;
export const LOCKOUT_DURATION   = 15 * 60 * 1000; // 15 minutes
