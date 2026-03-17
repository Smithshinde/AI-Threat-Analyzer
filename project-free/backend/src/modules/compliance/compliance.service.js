import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { stripUndefined } from '../../utils/helpers.js';

export async function listFrameworks() {
  const { data, error } = await supabase.from('frameworks').select('*').eq('is_active', true).order('name');
  if (error) throw new AppError(error.message);
  return data || [];
}

export async function getOrgFrameworks(orgId) {
  const { data, error } = await supabase
    .from('org_frameworks')
    .select('*, framework:framework_id(*)')
    .eq('org_id', orgId)
    .eq('is_active', true);
  if (error) throw new AppError(error.message);
  return data || [];
}

export async function activateFramework(orgId, frameworkId, userId, body) {
  const { data, error } = await supabase
    .from('org_frameworks')
    .upsert({ org_id: orgId, framework_id: frameworkId, ...body })
    .select('*, framework:framework_id(*)')
    .single();
  if (error) throw new AppError(error.message);
  return data;
}

export async function getComplianceScore(orgId, frameworkId) {
  let q = supabase
    .from('control_framework_mappings')
    .select(`
      id, compliance_status, control:control_id(id, control_id, title, status, effectiveness),
      requirement:requirement_id(requirement_id, title, category, framework:framework_id(name))
    `)
    .eq('org_id', orgId);

  if (frameworkId) {
    q = q.eq('requirement.framework_id', frameworkId);
  }

  const { data, error } = await q;
  if (error) throw new AppError(error.message);

  const items = (data || []).filter(d => d.requirement);
  const total  = items.length;
  const counts = { compliant: 0, partial: 0, non_compliant: 0, not_assessed: 0 };
  items.forEach(m => { counts[m.compliance_status] = (counts[m.compliance_status] || 0) + 1; });

  return {
    total,
    counts,
    score: total ? Math.round((counts.compliant / total) * 100) : 0,
    items,
  };
}

export async function getGapAnalysis(orgId, frameworkId) {
  // Get all requirements for the framework
  const { data: requirements } = await supabase
    .from('framework_requirements')
    .select('id, requirement_id, title, category, framework:framework_id(name)')
    .eq('framework_id', frameworkId);

  // Get existing mappings for org
  const { data: mappings } = await supabase
    .from('control_framework_mappings')
    .select('requirement_id, compliance_status, control:control_id(id, control_id, title)')
    .eq('org_id', orgId);

  const mappedIds = new Set((mappings || []).map(m => m.requirement_id));

  const gaps = (requirements || []).map(req => {
    const mapping = (mappings || []).find(m => m.requirement_id === req.id);
    return {
      ...req,
      mapped:            mappedIds.has(req.id),
      compliance_status: mapping?.compliance_status || 'not_assessed',
      control:           mapping?.control || null,
    };
  });

  const unmapped     = gaps.filter(g => !g.mapped).length;
  const nonCompliant = gaps.filter(g => g.compliance_status === 'non_compliant').length;

  return { total: gaps.length, unmapped, nonCompliant, gaps };
}

export async function mapControlToRequirement(orgId, controlId, requirementId, userId, body) {
  const { data, error } = await supabase
    .from('control_framework_mappings')
    .upsert({
      org_id: orgId, control_id: controlId, requirement_id: requirementId,
      mapped_by: userId,
      ...stripUndefined(body),
    })
    .select().single();

  if (error) throw new AppError(error.message);
  return data;
}

export async function getComplianceDashboard(orgId) {
  const { data: scores } = await supabase
    .from('v_compliance_score')
    .select('*')
    .eq('org_id', orgId);

  const { data: orgFrameworks } = await supabase
    .from('org_frameworks')
    .select('*, framework:framework_id(name)')
    .eq('org_id', orgId)
    .eq('is_active', true);

  return { scores: scores || [], frameworks: orgFrameworks || [] };
}
