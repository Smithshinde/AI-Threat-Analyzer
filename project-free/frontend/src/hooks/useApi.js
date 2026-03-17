import { useState, useEffect, useCallback } from 'react';

/**
 * Generic data-fetching hook.
 * Usage: const { data, loading, error, refetch } = useApi(someApiFn, [dep1])
 */
export function useApi(apiFn, deps = []) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFn();
      setData(res.data?.data ?? res.data);
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Unknown error');
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => { fetch(); }, [fetch]);

  return { data, loading, error, refetch: fetch };
}

/**
 * Mutation hook — for create/update/delete.
 */
export function useMutation(apiFn) {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);

  const mutate = async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFn(...args);
      return res.data?.data ?? res.data;
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Request failed';
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  return { mutate, loading, error };
}
