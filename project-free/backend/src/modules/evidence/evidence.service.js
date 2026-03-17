import { supabase } from '../../config/database.js';
import { AppError } from '../../utils/AppError.js';
import { generateId, parsePagination, sha256 } from '../../utils/helpers.js';

export async function listEvidence(orgId, query = {}) {
  const { from, to, page, limit } = parsePagination(query);
  let q = supabase
    .from('evidence')
    .select(`
      id, evidence_id, title, evidence_type, file_name, file_size, mime_type,
      collection_date, expiry_date, tags, created_at,
      collected_by:collected_by(id, first_name, last_name),
      control:control_id(id, control_id, title)
    `, { count: 'exact' })
    .eq('org_id', orgId).range(from, to).order('created_at', { ascending: false });

  if (query.control_id)    q = q.eq('control_id', query.control_id);
  if (query.evidence_type) q = q.eq('evidence_type', query.evidence_type);

  const { data, error, count } = await q;
  if (error) throw new AppError(error.message);
  return { data: data || [], pagination: { page, limit, total: count } };
}

export async function getEvidence(orgId, id) {
  const { data, error } = await supabase
    .from('evidence')
    .select('*, collected_by:collected_by(id, first_name, last_name, email), control:control_id(*)')
    .eq('org_id', orgId).eq('id', id).single();
  if (error || !data) throw AppError.notFound('Evidence not found');
  return data;
}

export async function createEvidence(orgId, userId, body, file) {
  const { count } = await supabase.from('evidence').select('*', { count: 'exact', head: true }).eq('org_id', orgId);
  const evidenceId = generateId('EVD', count || 0);

  const fileMeta = file ? {
    file_name:  file.originalname,
    file_path:  `evidence/${orgId}/${evidenceId}/${file.originalname}`,
    file_size:  file.size,
    mime_type:  file.mimetype,
    checksum:   sha256(file.buffer || file.originalname),
  } : {};

  const { data, error } = await supabase
    .from('evidence')
    .insert({ org_id: orgId, evidence_id: evidenceId, collected_by: userId, ...fileMeta, ...body })
    .select().single();

  if (error) throw new AppError(error.message);
  return data;
}

export async function deleteEvidence(orgId, id) {
  const existing = await getEvidence(orgId, id);
  const { error } = await supabase.from('evidence').delete().eq('org_id', orgId).eq('id', id);
  if (error) throw new AppError(error.message);
  return existing;
}
