import { Router } from 'express';
import multer from 'multer';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import { uploadLimiter } from '../../middleware/rateLimiter.js';
import * as svc from './evidence.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['application/pdf','image/png','image/jpeg','text/plain',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
    cb(null, allowed.includes(file.mimetype));
  },
});

const router = Router();
router.use(authenticate);

router.get('/', authorize('evidence:read'), async (req, res, next) => {
  try { const r = await svc.listEvidence(req.user.org_id, req.query); ok(res, r.data, { pagination: r.pagination }); } catch(e){next(e);}
});
router.get('/:id', authorize('evidence:read'), async (req, res, next) => {
  try { ok(res, await svc.getEvidence(req.user.org_id, req.params.id)); } catch(e){next(e);}
});
router.post('/', authorize('evidence:write'), uploadLimiter, upload.single('file'), async (req, res, next) => {
  try {
    const data = await svc.createEvidence(req.user.org_id, req.user.id, req.body, req.file);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'evidence.upload', resourceType: 'evidence', resourceId: data.id, newValues: { title: data.title, evidence_type: data.evidence_type }, req });
    created(res, data);
  } catch(e){next(e);}
});
router.delete('/:id', authorize('evidence:write'), async (req, res, next) => {
  try {
    await svc.deleteEvidence(req.user.org_id, req.params.id);
    res.status(204).send();
  } catch(e){next(e);}
});

export default router;
