import { Router } from 'express';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './audit.service.js';
import { ok, created } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/engagements',                        authorize('evidence:read'), async (req, res, next) => {
  try { const r = await svc.listEngagements(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.post('/engagements',                       authorize('evidence:write'), async (req, res, next) => {
  try { created(res, await svc.createEngagement(req.user.org_id, req.body)); } catch(e){next(e);}
});
router.get('/findings',                           authorize('evidence:read'), async (req, res, next) => {
  try { const r = await svc.listFindings(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.post('/engagements/:engagementId/findings', authorize('evidence:write'), async (req, res, next) => {
  try { created(res, await svc.createFinding(req.user.org_id, req.params.engagementId, req.body)); } catch(e){next(e);}
});
router.put('/findings/:id',                       authorize('evidence:write'), async (req, res, next) => {
  try { ok(res, await svc.updateFinding(req.user.org_id, req.params.id, req.body)); } catch(e){next(e);}
});
router.get('/logs',                               authorize('evidence:read'), async (req, res, next) => {
  try { const r = await svc.getAuditLogs(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});

export default router;
