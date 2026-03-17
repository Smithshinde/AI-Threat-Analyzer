import { Router } from 'express';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './reports.service.js';
import { ok } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/board',        authorize('reports:read'), async (req, res, next) => {
  try { ok(res, await svc.buildBoardReport(req.user.org_id)); } catch(e){next(e);}
});
router.get('/compliance',   authorize('reports:read'), async (req, res, next) => {
  try {
    if (!req.query.frameworkId) return res.status(400).json({ success: false, message: 'frameworkId required' });
    ok(res, await svc.buildComplianceReport(req.user.org_id, req.query.frameworkId));
  } catch(e){next(e);}
});
router.get('/risk-trend',   authorize('reports:read'), async (req, res, next) => {
  try { ok(res, await svc.buildRiskTrend(req.user.org_id, parseInt(req.query.months) || 6)); } catch(e){next(e);}
});

export default router;
