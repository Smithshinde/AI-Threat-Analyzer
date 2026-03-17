import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import Layout from './components/layout/Layout.jsx';
import Login from './pages/Login/Login.jsx';
import ExecutiveDashboard  from './pages/Dashboard/ExecutiveDashboard.jsx';
import CISODashboard       from './pages/Dashboard/CISODashboard.jsx';
import RiskRegister        from './pages/RiskRegister/RiskRegister.jsx';
import ComplianceView      from './pages/Compliance/ComplianceView.jsx';
import IncidentManagement  from './pages/Incidents/IncidentManagement.jsx';
import EvidenceRepository  from './pages/Evidence/EvidenceRepository.jsx';
import PolicyManagement    from './pages/Policies/PolicyManagement.jsx';
import Reports             from './pages/Reports/Reports.jsx';

function ProtectedRoute({ children, roles }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center"><div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"/></div>;
  if (!user)   return <Navigate to="/login" replace/>;
  if (roles?.length && !roles.includes(user.role)) return <Navigate to="/dashboard" replace/>;
  return children;
}

function AppRoutes() {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center"><div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"/></div>;

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/dashboard" replace/> : <Login/>}/>
      <Route path="/" element={<ProtectedRoute><Layout/></ProtectedRoute>}>
        <Route index element={<Navigate to="/dashboard" replace/>}/>
        <Route path="dashboard"  element={<ExecutiveDashboard/>}/>
        <Route path="ciso"       element={<ProtectedRoute roles={['ciso','admin','super_admin']}><CISODashboard/></ProtectedRoute>}/>
        <Route path="risks"      element={<RiskRegister/>}/>
        <Route path="compliance" element={<ComplianceView/>}/>
        <Route path="incidents"  element={<IncidentManagement/>}/>
        <Route path="evidence"   element={<EvidenceRepository/>}/>
        <Route path="policies"   element={<PolicyManagement/>}/>
        <Route path="reports"    element={<Reports/>}/>
        <Route path="controls"   element={<div className="p-8 text-center text-gray-400">Controls Library — coming soon</div>}/>
        <Route path="audit"      element={<div className="p-8 text-center text-gray-400">Audit Engagements — coming soon</div>}/>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace/>}/>
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes/>
      </AuthProvider>
    </BrowserRouter>
  );
}
