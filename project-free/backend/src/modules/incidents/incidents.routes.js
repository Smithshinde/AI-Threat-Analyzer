import { Router } from 'express';
import { body } from 'express-validator';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import * as svc from './incidents.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

const router = Router();
router.use(authenticate);

router.get('/',      authorize('incidents:read'), async (req, res, next) => {
  try { const r = await svc.listIncidents(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.get('/stats', authorize('incidents:read'), async (req, res, next) => {
  try { ok(res, await svc.getIncidentStats(req.user.org_id)); } catch(e){next(e);}
});
router.get('/:id',   authorize('incidents:read'), async (req, res, next) => {
  try { ok(res, await svc.getIncident(req.user.org_id, req.params.id)); } catch(e){next(e);}
});
router.post('/', authorize('incidents:write'),
  body('title').trim().notEmpty(),
  body('severity').isIn(['p1_critical','p2_high','p3_medium','p4_low']),
  body('detected_at').isISO8601(),
  async (req, res, next) => {
    try {
      const data = await svc.createIncident(req.user.org_id, req.user.id, req.body);
      await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'incident.create', resourceType: 'incident', resourceId: data.id, newValues: data, req });
      created(res, data);
    } catch(e){next(e);}
  }
);
router.put('/:id', authorize('incidents:write'), async (req, res, next) => {
  try {
    const result = await svc.updateIncident(req.user.org_id, req.params.id, req.body);
    ok(res, result.new);
  } catch(e){next(e);}
});
router.post('/:id/transition', authorize('incidents:write'),
  body('status').notEmpty(),
  async (req, res, next) => {
    try {
      const data = await svc.transitionStatus(req.user.org_id, req.params.id, req.body.status, req.user.id, req.body.notes);
      await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'incident.status_change', resourceType: 'incident', resourceId: req.params.id, newValues: { status: req.body.status }, req });
      ok(res, data);
    } catch(e){next(e);}
  }
);
router.post('/:id/timeline', authorize('incidents:write'), async (req, res, next) => {
  try {
    const entry = await svc.addTimelineEntry(req.params.id, req.body.action, req.body.description, req.user.id);
    created(res, entry);
  } catch(e){next(e);}
});

export default router;
