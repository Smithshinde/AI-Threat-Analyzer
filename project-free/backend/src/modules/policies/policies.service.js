import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, stripUndefined } from '../../utils/helpers.js';

const VALID_TRANSITIONS = {
  draft:        ['under_review'],
  under_review: ['approved', 'draft'],
  approved:     ['published'],
  published:    ['retired'],
  retired:      [],
};

export async function listPolicies(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  let q = supabase
    .from('policies')
    .select(`
      id, policy_id, title, category, status, version, effective_date, review_date,
      owner:owner_id(id, first_name, last_name)
    `, { count: 'exact' })
    .eq('org_id', orgId).range(from, to).order('updated_at', { ascending: false });

  if (query.status) q = q.eq('status', query.status);
  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function getPolicy(orgId, id) {
  const { data, error } = await supabase
    .from('policies')
    .select(`
      *,
      owner:owner_id(id, first_name, last_name, email),
      approver:approver_id(id, first_name, last_name, email),
      versions:policy_versions(version, change_summary, created_at, changed_by:changed_by(first_name, last_name))
    `)
    .eq('org_id', orgId).eq('id', id).single();
  if (error || !data) throw AppError.notFound('Policy not found');
  return data;
}

export async function createPolicy(orgId, userId, body) {
  const { count } = await supabase.from('policies').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const policyId = generateId('POL', count || 0);
  const { data, error } = await supabase
    .from('policies')
    .insert({ org_id: orgId, policy_id: policyId, created_by: userId, version: '1.0', ...body })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function updatePolicy(orgId, id, userId, body) {
  const existing = await getPolicy(orgId, id);
  if (existing.status === 'retired') throw AppError.badRequest('Cannot edit a retired policy');

  // Save version snapshot if content changed
  if (body.content && body.content !== existing.content) {
    const versionParts = existing.version.split('.');
    const newMinor = parseInt(versionParts[1] || 0) + 1;
    const newVersion = `${versionParts[0]}.${newMinor}`;
    await supabase.from('policy_versions').insert({
      policy_id: id, version: existing.version, content: existing.content, changed_by: userId, change_summary: body.change_summary || 'Content updated',
    });
    body.version = newVersion;
  }

  const { data, error } = await supabase
    .from('policies')
    .update(stripUndefined({ ...body, updated_at: new Date().toISOString() }))
    .eq('org_id', orgId).eq('id', id).select().single();
  if (error) throw new AppError(error.message);
  return { old: existing, new: data };
}

export async function transitionPolicyStatus(orgId, id, newStatus, userId) {
  const policy = await getPolicy(orgId, id);
  if (!VALID_TRANSITIONS[policy.status]?.includes(newStatus)) {
    throw AppError.badRequest(`Cannot transition policy from '${policy.status}' to '${newStatus}'`);
  }
  const updates = { status: newStatus };
  if (newStatus === 'approved') { updates.approver_id = userId; updates.approved_at = new Date().toISOString(); }
  if (newStatus === 'published') updates.effective_date = new Date().toISOString().split('T')[0];

  const { data, error } = await supabase
    .from('policies')
    .update(updates)
    .eq('org_id', orgId).eq('id', id).select().single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function acknowledgePolicy(policyId, userId, req) {
  const { data, error } = await supabase
    .from('policy_acknowledgements')
    .upsert({ policy_id: policyId, user_id: userId, ip_address: req.ip })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}
