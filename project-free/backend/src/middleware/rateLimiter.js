import rateLimit from 'express-rate-limit';

export const globalLimiter = rateLimit({
  windowMs: 60 * 1000,          // 1 minute
  max:      200,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, code: 'RATE_LIMITED', message: 'Too many requests, please slow down.' },
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,     // 15 minutes
  max:      20,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, code: 'RATE_LIMITED', message: 'Too many login attempts. Try again in 15 minutes.' },
});

export const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      30,
  message: { success: false, code: 'RATE_LIMITED', message: 'Upload rate limit exceeded.' },
});
