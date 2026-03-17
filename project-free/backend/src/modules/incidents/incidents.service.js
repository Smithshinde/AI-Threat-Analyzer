import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, stripUndefined } from '../../utils/helpers.js';

const SEVERITY_PRIORITY = { p1_critical: 4, p2_high: 3, p3_medium: 2, p4_low: 1 };
const STATUS_FLOW = {
  detected:    ['triaged'],
  triaged:     ['contained'],
  contained:   ['eradicated'],
  eradicated:  ['recovered'],
  recovered:   ['closed'],
  closed:      [],
};

export async function listIncidents(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  let q = supabase
    .from('incidents')
    .select(`
      id, incident_id, title, severity, status, category, detected_at, contained_at, resolved_at,
      assigned_to:assigned_to(id, first_name, last_name),
      reported_by:reported_by(id, first_name, last_name)
    `, { count: 'exact' })
    .eq('org_id', orgId)
    .range(from, to)
    .order('detected_at', { ascending: false });

  if (query.status)   q = q.eq('status', query.status);
  if (query.severity) q = q.eq('severity', query.severity);
  if (query.search)   q = q.ilike('title', `%${query.search}%`);

  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function getIncident(orgId, id) {
  const { data, error } = await supabase
    .from('incidents')
    .select(`
      *,
      assigned_to:assigned_to(id, first_name, last_name, email),
      reported_by:reported_by(id, first_name, last_name, email),
      incident_commander:incident_commander(id, first_name, last_name, email),
      timeline:incident_timeline(*, performed_by:performed_by(id, first_name, last_name))
    `)
    .eq('org_id', orgId).eq('id', id).single();

  if (error || !data) throw AppError.notFound('Incident not found');
  return data;
}

export async function createIncident(orgId, userId, body) {
  const { count } = await supabase.from('incidents').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const incidentId = generateId('INC', count || 0);

  const { data, error } = await supabase
    .from('incidents')
    .insert({ org_id: orgId, incident_id: incidentId, reported_by: userId, ...body })
    .select().single();

  if (error) throw new AppError(error.message);

  // Auto-create first timeline entry
  await addTimelineEntry(data.id, 'Incident Detected', body.description, userId);
  return data;
}

export async function updateIncident(orgId, id, body) {
  const existing = await getIncident(orgId, id);
  const { data, error } = await supabase
    .from('incidents')
    .update(stripUndefined({ ...body, updated_at: new Date().toISOString() }))
    .eq('org_id', orgId).eq('id', id)
    .select().single();

  if (error) throw new AppError(error.message);
  return { old: existing, new: data };
}

export async function transitionStatus(orgId, id, newStatus, userId, notes) {
  const incident = await getIncident(orgId, id);
  const allowed = STATUS_FLOW[incident.status] || [];
  if (!allowed.includes(newStatus)) {
    throw AppError.badRequest(`Cannot transition from '${incident.status}' to '${newStatus}'`);
  }

  const timestamps = {};
  if (newStatus === 'contained')  timestamps.contained_at = new Date().toISOString();
  if (newStatus === 'recovered')  timestamps.resolved_at  = new Date().toISOString();
  if (newStatus === 'closed')     timestamps.closed_at    = new Date().toISOString();

  const { data, error } = await supabase
    .from('incidents')
    .update({ status: newStatus, ...timestamps, updated_at: new Date().toISOString() })
    .eq('org_id', orgId).eq('id', id)
    .select().single();

  if (error) throw new AppError(error.message);

  await addTimelineEntry(id, `Status changed to: ${newStatus}`, notes, userId);
  return data;
}

export async function addTimelineEntry(incidentId, action, description, userId) {
  const { data, error } = await supabase
    .from('incident_timeline')
    .insert({ incident_id: incidentId, action, description, performed_by: userId })
    .select().single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function getIncidentStats(orgId) {
  const { data } = await supabase.from('incidents')
    .select('severity, status, detected_at, contained_at')
    .eq('org_id', orgId);

  const bySeverity = {}, byStatus = {};
  let totalMTTC = 0, mttrCount = 0;

  (data || []).forEach(inc => {
    bySeverity[inc.severity] = (bySeverity[inc.severity] || 0) + 1;
    byStatus[inc.status]     = (byStatus[inc.status] || 0) + 1;
    if (inc.contained_at) {
      const hours = (new Date(inc.contained_at) - new Date(inc.detected_at)) / 3600000;
      totalMTTC += hours; mttrCount++;
    }
  });

  return {
    total:       data?.length || 0,
    bySeverity,
    byStatus,
    mttr_hours:  mttrCount ? Math.round(totalMTTC / mttrCount) : null,
    open:        byStatus.detected + byStatus.triaged + byStatus.contained || 0,
  };
}
