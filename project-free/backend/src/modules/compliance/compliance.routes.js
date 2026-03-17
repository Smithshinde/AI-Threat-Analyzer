import { Router } from 'express';
import { body } from 'express-validator';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './compliance.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/frameworks',            authorize('compliance:read'), async (req, res, next) => {
  try { ok(res, await svc.listFrameworks()); } catch(e){next(e);}
});
router.get('/frameworks/org',        authorize('compliance:read'), async (req, res, next) => {
  try { ok(res, await svc.getOrgFrameworks(req.user.org_id)); } catch(e){next(e);}
});
router.post('/frameworks/:frameworkId/activate', authorize('compliance:write'), async (req, res, next) => {
  try { created(res, await svc.activateFramework(req.user.org_id, req.params.frameworkId, req.user.id, req.body)); } catch(e){next(e);}
});
router.get('/score',                 authorize('compliance:read'), async (req, res, next) => {
  try { ok(res, await svc.getComplianceScore(req.user.org_id, req.query.frameworkId)); } catch(e){next(e);}
});
router.get('/gap-analysis',          authorize('compliance:read'), async (req, res, next) => {
  try {
    if (!req.query.frameworkId) return res.status(400).json({ success: false, message: 'frameworkId required' });
    ok(res, await svc.getGapAnalysis(req.user.org_id, req.query.frameworkId));
  } catch(e){next(e);}
});
router.get('/dashboard',             authorize('compliance:read'), async (req, res, next) => {
  try { ok(res, await svc.getComplianceDashboard(req.user.org_id)); } catch(e){next(e);}
});
router.post('/mappings',             authorize('compliance:write'),
  body('controlId').isUUID(),
  body('requirementId').isUUID(),
  body('compliance_status').optional().isIn(['compliant','partial','non_compliant','not_assessed']),
  async (req, res, next) => {
    try {
      const { controlId, requirementId, ...rest } = req.body;
      const data = await svc.mapControlToRequirement(req.user.org_id, controlId, requirementId, req.user.id, rest);
      await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'compliance.map', resourceType: 'mapping', resourceId: data.id, newValues: data, req });
      created(res, data);
    } catch(e){next(e);}
  }
);

export default router;
