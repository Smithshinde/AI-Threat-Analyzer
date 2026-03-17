import { Router } from 'express';
import { body } from 'express-validator';
import * as ctrl from './auth.controller.js';
import { authenticate } from '../../middleware/auth.js';
import { authLimiter } from '../../middleware/rateLimiter.js';

const router = Router();

// Public routes
router.post('/login',
  authLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('orgSlug').notEmpty().trim(),
  ctrl.login
);

router.post('/refresh',
  body('refreshToken').notEmpty(),
  ctrl.refresh
);

// Protected routes
router.post('/logout', authenticate, ctrl.logout);
router.get('/profile', authenticate, ctrl.getProfile);

router.post('/register',
  authenticate,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 12 }).withMessage('Password must be at least 12 characters'),
  body('firstName').trim().notEmpty(),
  body('lastName').trim().notEmpty(),
  body('role').optional().isIn(['admin','ciso','risk_manager','auditor','viewer']),
  ctrl.register
);

router.post('/mfa/setup', authenticate, ctrl.setupMfa);

router.post('/mfa/verify',
  authenticate,
  body('code').isLength({ min: 6, max: 6 }).isNumeric(),
  ctrl.verifyMfa
);

router.post('/mfa/disable',
  authenticate,
  body('password').notEmpty(),
  ctrl.disableMfa
);

router.post('/change-password',
  authenticate,
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 12 }),
  ctrl.changePassword
);

export default router;
