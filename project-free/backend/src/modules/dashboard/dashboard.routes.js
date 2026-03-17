import { Router } from 'express';
import { authenticate } from '../../middleware/auth.js';
import * as svc from './dashboard.service.js';
import { ok } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/executive', async (req, res, next) => {
  try { ok(res, await svc.getExecutiveDashboard(req.user.org_id)); } catch(e){next(e);}
});
router.get('/ciso', async (req, res, next) => {
  try { ok(res, await svc.getCISODashboard(req.user.org_id)); } catch(e){next(e);}
});

export default router;
