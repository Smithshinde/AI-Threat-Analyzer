import axios from 'axios';
import { API_BASE } from '../utils/constants.js';

const api = axios.create({ baseURL: API_BASE, withCredentials: true });

// Attach access token from localStorage
api.interceptors.request.use(config => {
  const token = localStorage.getItem('accessToken');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config;
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        const refresh = localStorage.getItem('refreshToken');
        if (!refresh) throw new Error('No refresh token');
        const { data } = await axios.post(`${API_BASE}/auth/refresh`, { refreshToken: refresh });
        localStorage.setItem('accessToken', data.data.accessToken);
        original.headers.Authorization = `Bearer ${data.data.accessToken}`;
        return api(original);
      } catch {
        localStorage.clear();
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export default api;

// ── Module helpers ──────────────────────────────────────────────
export const authApi = {
  login:          (body) => api.post('/auth/login', body),
  logout:         (body) => api.post('/auth/logout', body),
  profile:        ()     => api.get('/auth/profile'),
  setupMfa:       ()     => api.post('/auth/mfa/setup'),
  verifyMfa:      (body) => api.post('/auth/mfa/verify', body),
  changePassword: (body) => api.post('/auth/change-password', body),
};

export const dashboardApi = {
  executive: () => api.get('/dashboard/executive'),
  ciso:      () => api.get('/dashboard/ciso'),
};

export const risksApi = {
  list:        (params) => api.get('/risks', { params }),
  get:         (id)     => api.get(`/risks/${id}`),
  create:      (body)   => api.post('/risks', body),
  update:      (id, b)  => api.put(`/risks/${id}`, b),
  remove:      (id)     => api.delete(`/risks/${id}`),
  heatmap:     ()       => api.get('/risks/heatmap'),
  linkControl: (id, b)  => api.post(`/risks/${id}/controls`, b),
};

export const controlsApi = {
  list:   (params) => api.get('/controls', { params }),
  get:    (id)     => api.get(`/controls/${id}`),
  create: (body)   => api.post('/controls', body),
  update: (id, b)  => api.put(`/controls/${id}`, b),
  remove: (id)     => api.delete(`/controls/${id}`),
  stats:  ()       => api.get('/controls/stats'),
};

export const complianceApi = {
  frameworks:       ()      => api.get('/compliance/frameworks'),
  orgFrameworks:    ()      => api.get('/compliance/frameworks/org'),
  score:            (fwId)  => api.get('/compliance/score', { params: { frameworkId: fwId } }),
  gapAnalysis:      (fwId)  => api.get('/compliance/gap-analysis', { params: { frameworkId: fwId } }),
  dashboard:        ()      => api.get('/compliance/dashboard'),
  mapControl:       (body)  => api.post('/compliance/mappings', body),
};

export const incidentsApi = {
  list:       (params) => api.get('/incidents', { params }),
  get:        (id)     => api.get(`/incidents/${id}`),
  create:     (body)   => api.post('/incidents', body),
  update:     (id, b)  => api.put(`/incidents/${id}`, b),
  transition: (id, b)  => api.post(`/incidents/${id}/transition`, b),
  addEntry:   (id, b)  => api.post(`/incidents/${id}/timeline`, b),
  stats:      ()       => api.get('/incidents/stats'),
};

export const evidenceApi = {
  list:   (params) => api.get('/evidence', { params }),
  get:    (id)     => api.get(`/evidence/${id}`),
  upload: (fd)     => api.post('/evidence', fd, { headers: { 'Content-Type': 'multipart/form-data' } }),
  remove: (id)     => api.delete(`/evidence/${id}`),
};

export const policiesApi = {
  list:        (params) => api.get('/policies', { params }),
  get:         (id)     => api.get(`/policies/${id}`),
  create:      (body)   => api.post('/policies', body),
  update:      (id, b)  => api.put(`/policies/${id}`, b),
  transition:  (id, b)  => api.post(`/policies/${id}/transition`, b),
  acknowledge: (id)     => api.post(`/policies/${id}/acknowledge`),
};

export const reportsApi = {
  board:      ()       => api.get('/reports/board'),
  compliance: (fwId)   => api.get('/reports/compliance', { params: { frameworkId: fwId } }),
  riskTrend:  (months) => api.get('/reports/risk-trend', { params: { months } }),
};

export const auditApi = {
  engagements: (params) => api.get('/audit/engagements', { params }),
  findings:    (params) => api.get('/audit/findings', { params }),
  logs:        (params) => api.get('/audit/logs', { params }),
};
