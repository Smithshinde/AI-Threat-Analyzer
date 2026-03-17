import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';

export async function getExecutiveDashboard(orgId) {
  const [riskSummary, complianceScores, incidentStats, kris, recentAuditLogs] = await Promise.all([
    // Risk summary from view
    supabase.from('v_risk_summary').select('*').eq('org_id', orgId).single(),
    // Compliance scores
    supabase.from('v_compliance_score').select('*').eq('org_id', orgId),
    // Active incidents
    supabase.from('incidents').select('severity, status').eq('org_id', orgId).neq('status', 'closed'),
    // KRI metrics
    supabase.from('kri_metrics').select('name, current_value, target_value, trend, threshold_green, threshold_amber, threshold_red, unit').eq('org_id', orgId).limit(6),
    // Recent activity
    supabase.from('audit_logs').select('action, created_at, user_id').eq('org_id', orgId).order('created_at', { ascending: false }).limit(5),
  ]);

  return {
    risks:      riskSummary.data || {},
    compliance: complianceScores.data || [],
    incidents:  summarizeIncidents(incidentStats.data || []),
    kris:       kris.data || [],
    activity:   recentAuditLogs.data || [],
  };
}

export async function getCISODashboard(orgId) {
  const [risks, controls, incidents, policies, evidence, findings] = await Promise.all([
    supabase.from('risks').select('status, inherent_score, residual_score, treatment_strategy').eq('org_id', orgId),
    supabase.from('controls').select('status, effectiveness, control_type').eq('org_id', orgId),
    supabase.from('incidents').select('severity, status, detected_at, contained_at').eq('org_id', orgId).order('detected_at', { ascending: false }).limit(10),
    supabase.from('policies').select('status').eq('org_id', orgId),
    supabase.from('evidence').select('id, created_at').eq('org_id', orgId).order('created_at', { ascending: false }).limit(1),
    supabase.from('audit_findings').select('severity, status').eq('org_id', orgId),
  ]);

  return {
    riskMetrics:     buildRiskMetrics(risks.data || []),
    controlMetrics:  buildControlMetrics(controls.data || []),
    recentIncidents: incidents.data || [],
    policyStats:     buildPolicyStats(policies.data || []),
    findingStats:    buildFindingStats(findings.data || []),
    evidenceCount:   evidence.count || 0,
  };
}

function summarizeIncidents(incidents) {
  const bySeverity = { p1_critical: 0, p2_high: 0, p3_medium: 0, p4_low: 0 };
  incidents.forEach(i => { if (bySeverity[i.severity] !== undefined) bySeverity[i.severity]++; });
  return { total: incidents.length, bySeverity };
}

function buildRiskMetrics(risks) {
  const byStatus = {}, byScore = { low: 0, medium: 0, high: 0, critical: 0 };
  let totalInherent = 0, totalResidual = 0, countResidual = 0;

  risks.forEach(r => {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    totalInherent += r.inherent_score || 0;
    if (r.residual_score) { totalResidual += r.residual_score; countResidual++; }
    const s = r.inherent_score;
    if (s >= 15) byScore.critical++;
    else if (s >= 9) byScore.high++;
    else if (s >= 4) byScore.medium++;
    else byScore.low++;
  });

  return {
    total:           risks.length,
    byStatus,
    byScore,
    avgInherent:     risks.length ? Math.round((totalInherent / risks.length) * 10) / 10 : 0,
    avgResidual:     countResidual ? Math.round((totalResidual / countResidual) * 10) / 10 : 0,
    riskReduction:   countResidual ? Math.round(((totalInherent / risks.length - totalResidual / countResidual) / (totalInherent / risks.length)) * 100) : 0,
  };
}

function buildControlMetrics(controls) {
  const byStatus = {}, byType = {};
  let totalEff = 0, effCount = 0;
  controls.forEach(c => {
    byStatus[c.status]       = (byStatus[c.status] || 0) + 1;
    byType[c.control_type]   = (byType[c.control_type] || 0) + 1;
    if (c.effectiveness != null) { totalEff += c.effectiveness; effCount++; }
  });
  return { total: controls.length, byStatus, byType, avgEffectiveness: effCount ? Math.round(totalEff / effCount) : 0 };
}

function buildPolicyStats(policies) {
  const byStatus = {};
  policies.forEach(p => { byStatus[p.status] = (byStatus[p.status] || 0) + 1; });
  return { total: policies.length, byStatus };
}

function buildFindingStats(findings) {
  const bySeverity = {}, byStatus = {};
  findings.forEach(f => {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byStatus[f.status]     = (byStatus[f.status] || 0) + 1;
  });
  return { total: findings.length, bySeverity, byStatus };
}
