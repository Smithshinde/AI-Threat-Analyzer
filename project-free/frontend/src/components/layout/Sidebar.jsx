import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, Shield, FileText, Zap,
  FolderOpen, ClipboardList, BarChart3, Settings, ChevronRight,
  ShieldCheck, BookOpen,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext.jsx';

const NAV = [
  { to: '/dashboard',    label: 'Executive Dashboard', icon: LayoutDashboard, roles: [] },
  { to: '/ciso',         label: 'CISO Dashboard',      icon: ShieldCheck,     roles: ['ciso','admin','super_admin'] },
  { label: 'Risk',       divider: true },
  { to: '/risks',        label: 'Risk Register',       icon: AlertTriangle,   roles: [] },
  { to: '/controls',     label: 'Controls',            icon: Shield,          roles: [] },
  { label: 'Governance', divider: true },
  { to: '/compliance',   label: 'Compliance',          icon: ClipboardList,   roles: [] },
  { to: '/policies',     label: 'Policies',            icon: BookOpen,        roles: [] },
  { label: 'Operations', divider: true },
  { to: '/incidents',    label: 'Incidents',           icon: Zap,             roles: [] },
  { to: '/evidence',     label: 'Evidence',            icon: FolderOpen,      roles: ['auditor','risk_manager','ciso','admin','super_admin'] },
  { to: '/audit',        label: 'Audit',               icon: FileText,        roles: ['auditor','ciso','admin','super_admin'] },
  { label: 'Analytics',  divider: true },
  { to: '/reports',      label: 'Reports',             icon: BarChart3,       roles: ['auditor','risk_manager','ciso','admin','super_admin'] },
];

export default function Sidebar({ collapsed }) {
  const { user } = useAuth();

  return (
    <aside className={`${collapsed ? 'w-16' : 'w-64'} h-screen bg-gray-900 flex flex-col transition-all duration-200 flex-shrink-0`}>
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-gray-800">
        <div className="bg-blue-600 p-1.5 rounded-lg flex-shrink-0">
          <ShieldCheck className="text-white" size={20}/>
        </div>
        {!collapsed && (
          <div>
            <p className="text-white font-bold text-sm leading-tight">GRC Platform</p>
            <p className="text-gray-400 text-xs">{user?.org_id?.slice(0,8)}…</p>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 overflow-y-auto">
        {NAV.map((item, i) => {
          if (item.divider) {
            return collapsed ? <div key={i} className="my-2 border-t border-gray-800"/> :
              <p key={i} className="px-4 mt-5 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">{item.label}</p>;
          }

          const allowed = !item.roles?.length || item.roles.includes(user?.role);
          if (!allowed) return null;

          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 mx-2 px-3 py-2.5 rounded-lg transition-colors mb-0.5 ${
                  isActive ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon size={18} className="flex-shrink-0"/>
                  {!collapsed && <span className="text-sm font-medium flex-1">{item.label}</span>}
                  {!collapsed && isActive && <ChevronRight size={14}/>}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* User */}
      {!collapsed && user && (
        <div className="border-t border-gray-800 px-4 py-3 flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            {user.first_name?.[0]}{user.last_name?.[0]}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white text-xs font-medium truncate">{user.first_name} {user.last_name}</p>
            <p className="text-gray-400 text-xs capitalize">{user.role?.replace('_',' ')}</p>
          </div>
        </div>
      )}
    </aside>
  );
}
