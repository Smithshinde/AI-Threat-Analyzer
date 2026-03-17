import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, stripUndefined } from '../../utils/helpers.js';
import { RISK_RATING, RISK_SCORE_MATRIX } from '../../config/constants.js';

export async function listRisks(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);

  let q = supabase
    .from('risks')
    .select(`
      id, risk_id, title, category, status, likelihood, impact, inherent_score,
      residual_likelihood, residual_impact, residual_score, treatment_strategy,
      review_date, target_date, tags, created_at, updated_at,
      owner:owner_id(id, first_name, last_name, email),
      asset:asset_id(id, name, asset_type)
    `, { count: 'exact' })
    .eq('org_id', orgId)
    .range(from, to)
    .order('inherent_score', { ascending: false });

  if (query.status)   q = q.eq('status', query.status);
  if (query.category) q = q.eq('category', query.category);
  if (query.owner_id) q = q.eq('owner_id', query.owner_id);
  if (query.search)   q = q.ilike('title', `%${query.search}%`);

  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);

  const enriched = (data || []).map(r => ({ ...r, rating: RISK_RATING(r.inherent_score) }));
  return { data: enriched, pagination: { page, limit, total: count } };
}

export async function getRisk(orgId, riskId) {
  const { data, error } = await supabase
    .from('risks')
    .select(`
      *,
      owner:owner_id(id, first_name, last_name, email),
      reviewer:reviewer_id(id, first_name, last_name, email),
      asset:asset_id(*),
      controls:risk_controls(control:control_id(id, control_id, title, status, effectiveness))
    `)
    .eq('org_id', orgId)
    .eq('id', riskId)
    .single();

  if (error || !data) throw AppError.notFound('Risk not found');
  return { ...data, rating: RISK_RATING(data.inherent_score) };
}

export async function createRisk(orgId, userId, body) {
  // Generate sequential risk_id
  const { count } = await supabase.from('risks').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const riskId = generateId('RSK', count || 0);

  // Calculate residual score if residual fields provided
  let residualScore = null;
  if (body.residual_likelihood && body.residual_impact) {
    residualScore = RISK_SCORE_MATRIX.likelihood[body.residual_likelihood] *
                    RISK_SCORE_MATRIX.impact[body.residual_impact];
  }

  const { data, error } = await supabase
    .from('risks')
    .insert({
      org_id: orgId, risk_id: riskId, created_by: userId,
      residual_score: residualScore,
      ...body,
    })
    .select()
    .single();

  if (error) throw new AppError(error.message);
  return data;
}

export async function updateRisk(orgId, riskId, body) {
  const existing = await getRisk(orgId, riskId);

  let residualScore = existing.residual_score;
  const rl = body.residual_likelihood || existing.residual_likelihood;
  const ri = body.residual_impact     || existing.residual_impact;
  if (rl && ri) {
    residualScore = RISK_SCORE_MATRIX.likelihood[rl] * RISK_SCORE_MATRIX.impact[ri];
  }

  const updates = stripUndefined({ ...body, residual_score: residualScore, updated_at: new Date().toISOString() });
  const { data, error } = await supabase
    .from('risks')
    .update(updates)
    .eq('org_id', orgId)
    .eq('id', riskId)
    .select()
    .single();

  if (error) throw new AppError(error.message);
  return { old: existing, new: data };
}

export async function deleteRisk(orgId, riskId) {
  const existing = await getRisk(orgId, riskId);
  const { error } = await supabase.from('risks').delete().eq('org_id', orgId).eq('id', riskId);
  if (error) throw new AppError(error.message);
  return existing;
}

export async function getRiskHeatmapData(orgId) {
  const { data } = await supabase
    .from('risks')
    .select('likelihood, impact, inherent_score, status')
    .eq('org_id', orgId)
    .neq('status', 'closed');

  const matrix = {};
  (data || []).forEach(r => {
    const key = `${r.likelihood}:${r.impact}`;
    matrix[key] = (matrix[key] || 0) + 1;
  });
  return matrix;
}

export async function linkControl(orgId, riskId, controlId, notes) {
  await getRisk(orgId, riskId); // validates ownership
  const { data, error } = await supabase
    .from('risk_controls')
    .upsert({ risk_id: riskId, control_id: controlId, notes })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}
