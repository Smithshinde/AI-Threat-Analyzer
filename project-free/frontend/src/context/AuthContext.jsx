import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi } from '../services/api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);

  const loadProfile = useCallback(async () => {
    const token = localStorage.getItem('accessToken');
    if (!token) { setLoading(false); return; }
    try {
      const { data } = await authApi.profile();
      setUser(data.data);
    } catch {
      localStorage.clear();
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadProfile(); }, [loadProfile]);

  const login = async (credentials) => {
    const { data } = await authApi.login(credentials);
    const { accessToken, refreshToken, user: u } = data.data;
    localStorage.setItem('accessToken',  accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    setUser(u);
    return u;
  };

  const logout = async () => {
    const refresh = localStorage.getItem('refreshToken');
    try { await authApi.logout({ refreshToken: refresh }); } catch { /* ignore */ }
    localStorage.clear();
    setUser(null);
  };

  const hasRole = (...roles) => roles.includes(user?.role);
  const canWrite = (resource) => {
    const writeRoles = { risks: ['risk_manager','ciso','admin','super_admin'], controls: ['risk_manager','ciso','admin','super_admin'], incidents: ['risk_manager','ciso','admin','super_admin'], policies: ['ciso','admin','super_admin'] };
    return writeRoles[resource]?.includes(user?.role) ?? false;
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, hasRole, canWrite }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};
