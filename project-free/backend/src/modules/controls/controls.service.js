import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, stripUndefined } from '../../utils/helpers.js';

export async function listControls(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  let q = supabase
    .from('controls')
    .select(`
      id, control_id, title, control_type, status, effectiveness,
      review_frequency, last_reviewed_at, next_review_date, created_at,
      owner:owner_id(id, first_name, last_name)
    `, { count: 'exact' })
    .eq('org_id', orgId)
    .range(from, to)
    .order('control_id');

  if (query.status)       q = q.eq('status', query.status);
  if (query.control_type) q = q.eq('control_type', query.control_type);
  if (query.search)       q = q.ilike('title', `%${query.search}%`);

  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function getControl(orgId, id) {
  const { data, error } = await supabase
    .from('controls')
    .select(`
      *,
      owner:owner_id(id, first_name, last_name, email),
      risks:risk_controls(risk:risk_id(id, risk_id, title, inherent_score, status)),
      mappings:control_framework_mappings(
        id, compliance_status, gap_description,
        requirement:requirement_id(requirement_id, title, framework:framework_id(name))
      )
    `)
    .eq('org_id', orgId).eq('id', id).single();

  if (error || !data) throw AppError.notFound('Control not found');
  return data;
}

export async function createControl(orgId, userId, body) {
  const { count } = await supabase.from('controls').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const controlId = generateId('CTL', count || 0);

  const { data, error } = await supabase
    .from('controls')
    .insert({ org_id: orgId, control_id: controlId, created_by: userId, ...body })
    .select().single();

  if (error) throw new AppError(error.message);
  return data;
}

export async function updateControl(orgId, id, body) {
  const existing = await getControl(orgId, id);
  const { data, error } = await supabase
    .from('controls')
    .update(stripUndefined({ ...body, updated_at: new Date().toISOString() }))
    .eq('org_id', orgId).eq('id', id)
    .select().single();

  if (error) throw new AppError(error.message);
  return { old: existing, new: data };
}

export async function deleteControl(orgId, id) {
  const existing = await getControl(orgId, id);
  const { error } = await supabase.from('controls').delete().eq('org_id', orgId).eq('id', id);
  if (error) throw new AppError(error.message);
  return existing;
}

export async function getControlStats(orgId) {
  const { data } = await supabase.from('controls')
    .select('status, effectiveness, control_type')
    .eq('org_id', orgId);

  const byStatus = {};
  const byType   = {};
  let totalEff = 0, count = 0;

  (data || []).forEach(c => {
    byStatus[c.status] = (byStatus[c.status] || 0) + 1;
    byType[c.control_type] = (byType[c.control_type] || 0) + 1;
    if (c.effectiveness != null) { totalEff += c.effectiveness; count++; }
  });

  return {
    total:               data?.length || 0,
    byStatus,
    byType,
    avgEffectiveness:    count ? Math.round(totalEff / count) : 0,
  };
}
