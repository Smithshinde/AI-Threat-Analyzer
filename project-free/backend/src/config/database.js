import { createClient } from '@supabase/supabase-js';
import logger from '../utils/logger.js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  logger.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

export const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

/**
 * Execute a query scoped to the tenant's org_id.
 * All service-layer queries should go through this helper.
 */
export function tenantQuery(table, orgId) {
  return supabase.from(table).select().eq('org_id', orgId);
}

export async function healthCheck() {
  const { error } = await supabase.from('organizations').select('id').limit(1);
  if (error) throw new Error(`DB health check failed: ${error.message}`);
  return true;
}
