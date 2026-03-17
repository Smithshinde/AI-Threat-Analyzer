import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';

/**
 * Gather all data needed for a Board-level summary report.
 */
export async function buildBoardReport(orgId) {
  const [org, riskSummary, complianceScores, incidentStats, openFindings] = await Promise.all([
    supabase.from('organizations').select('name, industry').eq('id', orgId).single(),
    supabase.from('v_risk_summary').select('*').eq('org_id', orgId).single(),
    supabase.from('v_compliance_score').select('*').eq('org_id', orgId),
    supabase.from('incidents').select('severity, status, detected_at').eq('org_id', orgId).gte('detected_at', new Date(Date.now() - 90*24*60*60*1000).toISOString()),
    supabase.from('audit_findings').select('severity, status').eq('org_id', orgId).neq('status', 'closed'),
  ]);

  const incidentsBySev = {};
  (incidentStats.data || []).forEach(i => { incidentsBySev[i.severity] = (incidentsBySev[i.severity] || 0) + 1; });

  return {
    generated_at:   new Date().toISOString(),
    organization:   org.data,
    reporting_period: 'Last 90 days',
    risk_summary:   riskSummary.data || {},
    compliance:     complianceScores.data || [],
    incidents:      { total: incidentStats.data?.length || 0, bySeverity: incidentsBySev },
    open_findings:  openFindings.data || [],
    key_messages:   generateKeyMessages(riskSummary.data, complianceScores.data, incidentStats.data),
  };
}

/**
 * Compliance report for a specific framework.
 */
export async function buildComplianceReport(orgId, frameworkId) {
  const { data: framework } = await supabase.from('frameworks').select('*').eq('id', frameworkId).single();
  if (!framework) throw AppError.notFound('Framework not found');

  const { data: mappings } = await supabase
    .from('control_framework_mappings')
    .select(`
      compliance_status, gap_description,
      control:control_id(control_id, title, status, effectiveness),
      requirement:requirement_id(requirement_id, title, category)
    `)
    .eq('org_id', orgId);

  const { data: evidence } = await supabase
    .from('evidence')
    .select('id, title, evidence_type, control_id, collection_date')
    .eq('org_id', orgId);

  const byStatus = { compliant: [], partial: [], non_compliant: [], not_assessed: [] };
  (mappings || []).forEach(m => {
    if (m.requirement) byStatus[m.compliance_status]?.push(m);
  });

  const total = mappings?.length || 0;
  const score = total ? Math.round((byStatus.compliant.length / total) * 100) : 0;

  return {
    generated_at:  new Date().toISOString(),
    framework:     framework,
    score,
    total_mapped:  total,
    by_status:     { compliant: byStatus.compliant.length, partial: byStatus.partial.length, non_compliant: byStatus.non_compliant.length, not_assessed: byStatus.not_assessed.length },
    gaps:          [...byStatus.non_compliant, ...byStatus.not_assessed],
    evidence_count: evidence?.length || 0,
  };
}

/**
 * Risk trend data for the last N months.
 */
export async function buildRiskTrend(orgId, months = 6) {
  const since = new Date();
  since.setMonth(since.getMonth() - months);

  const { data } = await supabase
    .from('risks')
    .select('inherent_score, residual_score, status, created_at, updated_at')
    .eq('org_id', orgId)
    .gte('created_at', since.toISOString());

  // Group by month
  const byMonth = {};
  (data || []).forEach(r => {
    const month = r.created_at.slice(0, 7);
    if (!byMonth[month]) byMonth[month] = { month, new_risks: 0, closed: 0, critical: 0 };
    byMonth[month].new_risks++;
    if (r.status === 'closed')         byMonth[month].closed++;
    if (r.inherent_score >= 15)        byMonth[month].critical++;
  });

  return { period_months: months, trend: Object.values(byMonth).sort((a, b) => a.month.localeCompare(b.month)) };
}

function generateKeyMessages(riskSummary, complianceScores, incidents) {
  const messages = [];
  if (riskSummary?.critical_risks > 0) {
    messages.push(`⚠️ ${riskSummary.critical_risks} critical risk(s) require immediate board attention.`);
  }
  const lowCompliance = (complianceScores || []).filter(c => c.compliance_percentage < 70);
  if (lowCompliance.length) {
    messages.push(`📋 ${lowCompliance.length} framework(s) below 70% compliance threshold.`);
  }
  const p1 = (incidents || []).filter(i => i.severity === 'p1_critical').length;
  if (p1 > 0) {
    messages.push(`🚨 ${p1} P1 Critical incident(s) recorded in the reporting period.`);
  }
  if (!messages.length) messages.push('✅ No critical issues requiring immediate board action.');
  return messages;
}
