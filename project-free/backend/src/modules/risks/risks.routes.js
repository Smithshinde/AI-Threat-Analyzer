import { Router } from 'express';
import { body } from 'express-validator';
import * as ctrl from './risks.controller.js';
import { authenticate } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';

const router = Router();
router.use(authenticate);

const riskValidation = [
  body('title').trim().notEmpty().isLength({ max: 500 }),
  body('likelihood').isIn(['rare','unlikely','possible','likely','almost_certain']),
  body('impact').isIn(['negligible','minor','moderate','major','critical']),
  body('category').optional().trim(),
  body('treatment_strategy').optional().isIn(['mitigate','accept','transfer','avoid']),
];

router.get('/',        authorize('risks:read'),   ctrl.list);
router.get('/heatmap', authorize('risks:read'),   ctrl.heatmap);
router.get('/:id',     authorize('risks:read'),   ctrl.getOne);
router.post('/',       authorize('risks:write'),  riskValidation, ctrl.create);
router.put('/:id',     authorize('risks:write'),  riskValidation, ctrl.update);
router.delete('/:id',  authorize('risks:delete'), ctrl.remove);
router.post('/:id/controls', authorize('risks:write'), ctrl.linkControl);

export default router;
