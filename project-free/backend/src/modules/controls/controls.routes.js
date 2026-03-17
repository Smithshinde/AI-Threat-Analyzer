import { Router } from 'express';
import { body } from 'express-validator';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './controls.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/',      authorize('controls:read'), async (req, res, next) => {
  try { const r = await svc.listControls(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.get('/stats', authorize('controls:read'), async (req, res, next) => {
  try { ok(res, await svc.getControlStats(req.user.org_id)); } catch(e){next(e);}
});
router.get('/:id',   authorize('controls:read'), async (req, res, next) => {
  try { ok(res, await svc.getControl(req.user.org_id, req.params.id)); } catch(e){next(e);}
});
router.post('/', authorize('controls:write'),
  body('title').trim().notEmpty(),
  body('control_type').isIn(['preventive','detective','corrective','deterrent','compensating']),
  async (req, res, next) => {
    try {
      const data = await svc.createControl(req.user.org_id, req.user.id, req.body);
      await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'control.create', resourceType: 'control', resourceId: data.id, newValues: data, req });
      created(res, data);
    } catch(e){next(e);}
  }
);
router.put('/:id', authorize('controls:write'), async (req, res, next) => {
  try {
    const result = await svc.updateControl(req.user.org_id, req.params.id, req.body);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'control.update', resourceType: 'control', resourceId: req.params.id, oldValues: result.old, newValues: result.new, req });
    ok(res, result.new);
  } catch(e){next(e);}
});
router.delete('/:id', authorize('controls:delete'), async (req, res, next) => {
  try {
    await svc.deleteControl(req.user.org_id, req.params.id);
    res.status(204).send();
  } catch(e){next(e);}
});

export default router;
