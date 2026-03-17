import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, stripUndefined } from '../../utils/helpers.js';

export async function listEngagements(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  const { data, error, count } = await supabase
    .from('audit_engagements')
    .select(`
      id, audit_id, title, audit_type, status, start_date, end_date, report_date,
      framework:framework_id(name),
      lead_auditor:lead_auditor_id(id, first_name, last_name)
    `, { count: 'exact' })
    .eq('org_id', orgId).range(from, to).order('start_date', { ascending: false });
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function createEngagement(orgId, body) {
  const { count } = await supabase.from('audit_engagements').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const auditId = generateId('AUD', count || 0);
  const { data, error } = await supabase
    .from('audit_engagements')
    .insert({ org_id: orgId, audit_id: auditId, ...body })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function listFindings(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  let q = supabase
    .from('audit_findings')
    .select(`
      id, finding_id, title, severity, status, due_date, remediated_at,
      control:control_id(id, control_id, title),
      engagement:engagement_id(audit_id, title),
      owner:owner_id(id, first_name, last_name)
    `, { count: 'exact' })
    .eq('org_id', orgId).range(from, to).order('created_at', { ascending: false });

  if (query.status)   q = q.eq('status', query.status);
  if (query.severity) q = q.eq('severity', query.severity);

  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function createFinding(orgId, engagementId, body) {
  const { count } = await supabase.from('audit_findings').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const findingId = generateId('FND', count || 0);
  const { data, error } = await supabase
    .from('audit_findings')
    .insert({ org_id: orgId, engagement_id: engagementId, finding_id: findingId, ...body })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function updateFinding(orgId, id, body) {
  const { data, error } = await supabase
    .from('audit_findings')
    .update(stripUndefined({ ...body, updated_at: new Date().toISOString() }))
    .eq('org_id', orgId).eq('id', id).select().single();
  if (error || !data) throw AppError.notFound('Finding not found');
  return data;
}

export async function getAuditLogs(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  const { data, error, count } = await supabase
    .from('audit_logs')
    .select('id, action, resource_type, resource_id, ip_address, created_at, user:user_id(id, first_name, last_name, email)', { count: 'exact' })
    .eq('org_id', orgId)
    .order('created_at', { ascending: false })
    .range(from, to);
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}
