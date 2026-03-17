import { Bell, Menu, LogOut, User } from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import { useNavigate } from 'react-router-dom';

export default function Header({ onToggleSidebar, title }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="h-16 bg-white border-b border-gray-200 flex items-center px-6 gap-4">
      <button onClick={onToggleSidebar} className="p-1.5 rounded-lg text-gray-500 hover:bg-gray-100 transition-colors">
        <Menu size={20}/>
      </button>

      <h1 className="font-semibold text-gray-900 text-sm flex-1">{title}</h1>

      <div className="flex items-center gap-2">
        <button className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 relative">
          <Bell size={18}/>
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full"/>
        </button>

        <div className="relative">
          <button
            onClick={() => setMenuOpen(o => !o)}
            className="flex items-center gap-2 pl-2 pr-3 py-1.5 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">
              {user?.first_name?.[0]}{user?.last_name?.[0]}
            </div>
            <span className="text-sm text-gray-700 font-medium">{user?.first_name}</span>
          </button>

          {menuOpen && (
            <div className="absolute right-0 mt-1 w-48 bg-white rounded-xl shadow-lg border border-gray-100 py-1 z-50">
              <div className="px-4 py-2 border-b border-gray-100">
                <p className="text-sm font-medium text-gray-900">{user?.first_name} {user?.last_name}</p>
                <p className="text-xs text-gray-500 capitalize">{user?.role?.replace('_',' ')}</p>
              </div>
              <button className="flex items-center gap-2 w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50">
                <User size={15}/> Profile
              </button>
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
              >
                <LogOut size={15}/> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
