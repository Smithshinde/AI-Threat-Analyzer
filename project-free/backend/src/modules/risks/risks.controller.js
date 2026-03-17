import { validationResult } from 'express-validator';
import * as svc from './risks.service.js';
import { writeAuditLog } from '../../middleware/auditLog.js';
import { ok, created } from '../../utils/helpers.js';

function validate(req) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const err = new Error('Validation'); err.type = 'validation'; err.errors = errors.array(); throw err;
  }
}

export const list   = async (req, res, next) => {
  try { ok(res, ...[await svc.listRisks(req.user.org_id, req.query)].map(r => [r.data, { pagination: r.pagination }]).flat()); }
  catch (e) { next(e); }
};

export const getOne = async (req, res, next) => {
  try { ok(res, await svc.getRisk(req.user.org_id, req.params.id)); }
  catch (e) { next(e); }
};

export const create = async (req, res, next) => {
  try {
    validate(req);
    const data = await svc.createRisk(req.user.org_id, req.user.id, req.body);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'risk.create', resourceType: 'risk', resourceId: data.id, newValues: data, req });
    created(res, data);
  } catch (e) { next(e); }
};

export const update = async (req, res, next) => {
  try {
    validate(req);
    const result = await svc.updateRisk(req.user.org_id, req.params.id, req.body);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'risk.update', resourceType: 'risk', resourceId: req.params.id, oldValues: result.old, newValues: result.new, req });
    ok(res, result.new);
  } catch (e) { next(e); }
};

export const remove = async (req, res, next) => {
  try {
    const old = await svc.deleteRisk(req.user.org_id, req.params.id);
    await writeAuditLog({ orgId: req.user.org_id, userId: req.user.id, action: 'risk.delete', resourceType: 'risk', resourceId: req.params.id, oldValues: old, req });
    res.status(204).send();
  } catch (e) { next(e); }
};

export const heatmap = async (req, res, next) => {
  try { ok(res, await svc.getRiskHeatmapData(req.user.org_id)); }
  catch (e) { next(e); }
};

export const linkControl = async (req, res, next) => {
  try {
    const data = await svc.linkControl(req.user.org_id, req.params.id, req.body.controlId, req.body.notes);
    created(res, data);
  } catch (e) { next(e); }
};
