import { Router } from 'express';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './policies.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/', authorize('policies:read'), async (req, res, next) => {
  try { const r = await svc.listPolicies(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.get('/:id', authorize('policies:read'), async (req, res, next) => {
  try { ok(res, await svc.getPolicy(req.user.org_id, req.params.id)); } catch(e){next(e);}
});
router.post('/', authorize('policies:write'), async (req, res, next) => {
  try {
    const data = await svc.createPolicy(req.user.org_id, req.user.id, req.body);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'policy.create', resourceType: 'policy', resourceId: data.id, newValues: data, req });
    created(res, data);
  } catch(e){next(e);}
});
router.put('/:id', authorize('policies:write'), async (req, res, next) => {
  try {
    const result = await svc.updatePolicy(req.user.org_id, req.params.id, req.user.id, req.body);
    ok(res, result.new);
  } catch(e){next(e);}
});
router.post('/:id/transition', authorize('policies:approve'), async (req, res, next) => {
  try {
    const data = await svc.transitionPolicyStatus(req.user.org_id, req.params.id, req.body.status, req.user.id);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'policy.status_change', resourceType: 'policy', resourceId: req.params.id, newValues: { status: req.body.status }, req });
    ok(res, data);
  } catch(e){next(e);}
});
router.post('/:id/acknowledge', authorize('policies:read'), async (req, res, next) => {
  try {
    const data = await svc.acknowledgePolicy(req.params.id, req.user.id, req);
    created(res, data);
  } catch(e){next(e);}
});

export default router;
