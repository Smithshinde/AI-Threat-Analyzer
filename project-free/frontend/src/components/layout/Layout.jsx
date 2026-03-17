import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar.jsx';
import Header from './Header.jsx';

const TITLES = {
  '/dashboard': 'Executive Dashboard',
  '/ciso':      'CISO Dashboard',
  '/risks':     'Risk Register',
  '/controls':  'Controls Library',
  '/compliance':'Compliance Mapping',
  '/policies':  'Policy Management',
  '/incidents': 'Incident Management',
  '/evidence':  'Evidence Repository',
  '/audit':     'Audit & Findings',
  '/reports':   'Reports & Analytics',
};

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const title = TITLES[pathname] || TITLES[Object.keys(TITLES).find(k => pathname.startsWith(k))] || 'GRC Platform';

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      <Sidebar collapsed={collapsed}/>
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header onToggleSidebar={() => setCollapsed(c => !c)} title={title}/>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet/>
        </main>
      </div>
    </div>
  );
}
